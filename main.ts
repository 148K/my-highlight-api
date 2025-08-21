import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import { decode as base64Decode, encode as base64Encode } from "https://deno.land/std@0.208.0/encoding/base64.ts";

interface UserInfo {
  rt: string;
  user_id: string;
  email: string;
  client_uuid: string;
}

interface Message {
  role: string;
  content: string | OpenAIMessageContent[] | null;
  tool_call_id?: string;
  tool_calls?: any[];
}

interface OpenAIMessageContent {
  type: "text" | "image_url";
  text?: string;
  image_url?: { [key: string]: string };
}

interface OpenAITool {
  type: "function";
  function: {
    name: string;
    description?: string;
    parameters?: any;
  };
}

interface ChatCompletionRequest {
  messages: Message[];
  stream?: boolean;
  model?: string;
  tools?: OpenAITool[];
}

const HIGHLIGHT_BASE_URL = "https://chat-backend.highlightai.com";
const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Highlight/1.3.61 Chrome/132.0.6834.210 Electron/34.5.8 Safari/537.36";

const accessTokens: Map<string, { access_token: string; expires_at: number }> = new Map();
const modelCache: Map<string, any> = new Map();

const Hr = {
  r: [87, 78, 72, 56, 79, 48, 122, 79, 107, 104, 82, 119, 51, 100, 78, 90, 85, 85, 69, 107, 90, 116, 87, 48, 108,
      53, 83, 84, 70, 81, 121, 69],
  m: [27, 26, 25, 22, 24, 21, 17, 12, 30, 19, 20, 14, 31, 8, 18, 10, 13, 5, 29, 7, 16, 6, 28, 23, 9, 15, 4, 0, 11,
      2, 3, 1]
};

const jr = {
  r: [87, 90, 109, 107, 53, 105, 81, 89, 103, 107, 68, 49, 68, 105, 106, 77, 49, 106, 53, 78, 77, 78, 106, 106, 61,
      77, 89, 51, 66, 79, 86, 89, 106, 65, 106, 52, 89, 77, 87, 106, 89, 122, 78, 90, 65, 89, 50, 105, 61, 90, 106,
      66, 48, 53, 71, 89, 87, 52, 81, 84, 78, 90, 74, 78, 103, 50, 70, 79, 51, 50, 50, 77, 122, 108, 84, 81, 120,
      90, 89, 89, 89, 79, 119, 122, 121, 108, 69, 77],
  m: [65, 20, 1, 6, 31, 63, 74, 12, 85, 78, 33, 3, 41, 19, 45, 52, 75, 21, 23, 16, 56, 36, 5, 71, 87, 68, 72, 15,
      18, 32, 82, 8, 17, 54, 83, 35, 28, 48, 49, 77, 30, 25, 10, 38, 22, 50, 29, 11, 86, 64, 57, 70, 47, 67, 81, 44,
      61, 7, 58, 13, 84, 76, 42, 24, 46, 37, 62, 80, 27, 51, 73, 34, 69, 39, 53, 2, 79, 60, 26, 0, 66, 40, 55, 9,
      59, 43, 14, 4]
};

async function pbkdf2(password: string, salt: Uint8Array, iterations: number, keyLen: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: iterations,
      hash: "SHA-256"
    },
    key,
    keyLen * 8
  );
  
  return new Uint8Array(derivedBits);
}

function Ah(n: number[], e: number[]): number[] {
  const t: number[] = new Array(n.length);
  for (let s = 0; s < e.length; s++) {
    t[e[s]] = n[s];
  }
  return t;
}

function Fl(n: number[], e: number[]): string {
  const t = Ah(n, e);
  const s = String.fromCharCode(...t);
  const o = base64Decode(s);
  const i = Array.from(new Uint8Array(o)).reverse();
  return new TextDecoder().decode(new Uint8Array(i));
}

async function Th(n: string): Promise<Uint8Array> {
  const salt = new TextEncoder().encode(Fl(Hr.r, Hr.m));
  return await pbkdf2(n, salt, 100000, 32);
}

async function kh(n: { userId: string; clientUUID: string }, fixedIv?: Uint8Array): Promise<string> {
  const e = await Th(n.userId);
  const t = fixedIv || crypto.getRandomValues(new Uint8Array(16));
  
  const data = {
    ...n,
    apiKey: Fl(jr.r, jr.m)
  };
  
  const jsonStr = JSON.stringify(data);
  const jsonBytes = new TextEncoder().encode(jsonStr);
  
  // PKCS7 padding
  const padLen = 16 - (jsonBytes.length % 16);
  const paddedData = new Uint8Array(jsonBytes.length + padLen);
  paddedData.set(jsonBytes);
  paddedData.fill(padLen, jsonBytes.length);
  
  const key = await crypto.subtle.importKey("raw", e, { name: "AES-CBC" }, false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-CBC", iv: t }, key, paddedData);
  
  const tHex = Array.from(t).map(b => b.toString(16).padStart(2, '0')).join('');
  const encryptedHex = Array.from(new Uint8Array(encrypted)).map(b => b.toString(16).padStart(2, '0')).join('');
  
  return `${tHex}:${encryptedHex}`;
}

function H7t(t = 12): string {
  const randomBytes = crypto.getRandomValues(new Uint8Array(t));
  return Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getIdentifier(userId: string, clientUUID: string, fixedIv?: Uint8Array): Promise<string> {
  const t = await kh({ userId, clientUUID }, fixedIv);
  return `${H7t()}:${t}`;
}

// 登录功能
async function login(code: string): Promise<UserInfo> {
  console.log("开始登录流程...");
  
  const chromeDeviceId = crypto.randomUUID();
  const deviceId = crypto.randomUUID();
  
  // 第一步：交换code获取tokens
  const exchangeResponse = await fetch(`${HIGHLIGHT_BASE_URL}/api/v1/auth/exchange`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      code: code,
      amplitudeDeviceId: chromeDeviceId,
    }),
  });
  
  if (!exchangeResponse.ok) {
    const errorText = await exchangeResponse.text();
    console.error(`HTTP错误: ${exchangeResponse.status} ${errorText}`);
    
    if (exchangeResponse.status === 500) {
      throw new Error("服务器内部错误，请稍后重试");
    } else if (exchangeResponse.status === 400) {
      throw new Error("请求格式错误，请检查授权代码是否正确");
    } else {
      throw new Error(`登录服务暂时不可用 (错误代码: ${exchangeResponse.status})`);
    }
  }
  
  const exchangeData = await exchangeResponse.json();
  if (!exchangeData.success) {
    console.error(`登录失败详情:`, exchangeData);
    
    // 友好的错误消息映射
    const errorMessage = exchangeData.error || "未知错误";
    
    if (errorMessage.includes("expired") || errorMessage.includes("invalid")) {
      throw new Error("授权代码已过期或无效。授权代码只能使用一次，请重新登录获取新的代码。");
    } else if (errorMessage.includes("not found")) {
      throw new Error("授权代码不存在，请检查是否复制完整。");
    } else if (errorMessage.includes("already used")) {
      throw new Error("此授权代码已被使用过，请重新登录获取新的代码。");
    } else if (errorMessage.includes("rate limit")) {
      throw new Error("请求过于频繁，请稍等片刻后重试。");
    } else {
      throw new Error(`登录失败: ${errorMessage}。如果问题持续存在，请重新获取授权代码。`);
    }
  }
  
  const accessToken = exchangeData.data.accessToken;
  const refreshToken = exchangeData.data.refreshToken;
  
  // 第二步：注册客户端
  const clientResponse = await fetch(`${HIGHLIGHT_BASE_URL}/api/v1/users/me/client`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
    },
    body: JSON.stringify({
      client_uuid: deviceId,
    }),
  });
  
  if (!clientResponse.ok) {
    console.warn(`客户端注册失败: ${clientResponse.status}，但继续进行...`);
  }
  
  // 第三步：获取用户信息
  const profileResponse = await fetch(`${HIGHLIGHT_BASE_URL}/api/v1/auth/profile`, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
    },
  });
  
  if (!profileResponse.ok) {
    const errorText = await profileResponse.text();
    console.error(`获取用户信息失败: ${profileResponse.status} ${errorText}`);
    throw new Error(`无法获取用户信息，请重试。如果问题持续存在，请重新登录。`);
  }
  
  const profileData = await profileResponse.json();
  const userId = profileData.id;
  const email = profileData.email;
  
  console.log(`登录成功: ${userId} ${email}`);
  
  const userInfo: UserInfo = {
    rt: refreshToken,
    user_id: userId,
    email: email,
    client_uuid: deviceId,
  };
  
  // 生成API Key
  const apiKey = base64Encode(new TextEncoder().encode(JSON.stringify(userInfo)));
  console.log("----API KEY----");
  console.log(apiKey);
  console.log("----API KEY----");
  
  return userInfo;
}

// 工具函数
function parseApiKey(apiKeyBase64: string): UserInfo | null {
  try {
    const decoded = new TextDecoder().decode(base64Decode(apiKeyBase64));
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

function parseJwtPayload(jwtToken: string): any | null {
  try {
    const parts = jwtToken.split(".");
    if (parts.length !== 3) return null;
    
    let payload = parts[1];
    const padding = payload.length % 4;
    if (padding) {
      payload += "=".repeat(4 - padding);
    }
    
    const decoded = new TextDecoder().decode(base64Decode(payload));
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

async function refreshAccessToken(rt: string): Promise<string> {
  const response = await fetch(`${HIGHLIGHT_BASE_URL}/api/v1/auth/refresh`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ refreshToken: rt }),
  });
  
  if (!response.ok) {
    throw new Error("无法刷新access token");
  }
  
  const respJson = await response.json();
  if (!respJson.success) {
    throw new Error("刷新access token失败");
  }
  
  const newAccessToken = respJson.data.accessToken;
  const payload = parseJwtPayload(newAccessToken);
  const expiresAt = payload?.exp || Math.floor(Date.now() / 1000) + 3600;
  
  accessTokens.set(rt, {
    access_token: newAccessToken,
    expires_at: expiresAt,
  });
  
  return newAccessToken;
}

async function getAccessToken(rt: string): Promise<string> {
  const tokenInfo = accessTokens.get(rt);
  const currentTime = Math.floor(Date.now() / 1000);
  
  if (tokenInfo && tokenInfo.expires_at > currentTime + 60) {
    return tokenInfo.access_token;
  }
  
  return await refreshAccessToken(rt);
}

async function fetchModelsFromUpstream(accessToken: string): Promise<void> {
  const response = await fetch(`${HIGHLIGHT_BASE_URL}/api/v1/models`, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'User-Agent': USER_AGENT,
    },
  });
  
  if (!response.ok) {
    throw new Error("获取模型列表失败");
  }
  
  const respJson = await response.json();
  if (!respJson.success) {
    throw new Error("获取模型数据失败");
  }
  
  modelCache.clear();
  for (const model of respJson.data) {
    modelCache.set(model.name, {
      id: model.id,
      name: model.name,
      provider: model.provider,
      isFree: model.pricing?.isFree || false,
    });
  }
}

async function getModels(accessToken: string): Promise<Map<string, any>> {
  if (modelCache.size === 0) {
    await fetchModelsFromUpstream(accessToken);
  }
  return modelCache;
}

function getHighlightHeaders(accessToken: string, identifier?: string): Record<string, string> {
  const headers: Record<string, string> = {
    "accept": "*/*",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "zh-CN",
    "authorization": `Bearer ${accessToken}`,
    "content-type": "application/json",
    "user-agent": USER_AGENT,
  };
  
  if (identifier) {
    headers["identifier"] = identifier;
  }
  
  return headers;
}

function formatMessagesToPrompt(messages: Message[]): string {
  const formattedMessages: string[] = [];
  for (const message of messages) {
    if (message.role) {
      if (message.content) {
        if (Array.isArray(message.content)) {
          for (const item of message.content) {
            formattedMessages.push(`${message.role}: ${item.text}`);
          }
        } else {
          formattedMessages.push(`${message.role}: ${message.content}`);
        }
      }
      if (message.tool_calls) {
        formattedMessages.push(`${message.role}: ${JSON.stringify(message.tool_calls)}`);
      }
      if (message.tool_call_id) {
        formattedMessages.push(`${message.role}: tool_call_id: ${message.tool_call_id} ${message.content}`);
      }
    }
  }
  return formattedMessages.join("\n\n");
}

function formatOpenAITools(openaiTools?: OpenAITool[]): any[] {
  if (!openaiTools) return [];
  
  return openaiTools.map(tool => ({
    name: tool.function.name,
    description: tool.function.description,
    parameters: tool.function.parameters,
  }));
}

// CORS 头部生成函数
function getCorsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
    "Access-Control-Max-Age": "86400", // 24小时
  };
}

// 处理预检请求
function handleOptionsRequest(): Response {
  return new Response(null, {
    status: 204,
    headers: getCorsHeaders()
  });
}

// HTTP处理函数
async function handleRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  
  // 处理预检请求
  if (request.method === "OPTIONS") {
    return handleOptionsRequest();
  }

  // 前端页面
  if (path === "/" || path === "/index.html") {
    const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Highlight AI API</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: #f5f5f7;
            color: #1d1d1f;
            line-height: 1.6;
            font-size: 16px;
            -webkit-font-smoothing: antialiased;
            text-rendering: optimizeLegibility;
        }
        
        .container {
            max-width: 720px;
            margin: 0 auto;
            padding: 20px 16px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid #e5e5e7;
        }
        
        .header h1 {
            font-size: 36px;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: #1d1d1f;
            margin-bottom: 12px;
        }
        
        .header p {
            font-size: 18px;
            color: #6e6e73;
            font-weight: 400;
        }
        
        .section {
            background: #ffffff;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            border: 1px solid #e5e5e7;
        }
        
        .section-title {
            font-size: 20px;
            font-weight: 600;
            color: #1d1d1f;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .step-number {
            width: 28px;
            height: 28px;
            background: #1d1d1f;
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: 600;
        }
        
        .section-content {
            color: #6e6e73;
            font-size: 15px;
            line-height: 1.4;
            margin-bottom: 16px;
        }
        
        .url-box {
            background: #f5f5f7;
            border: 1px solid #d2d2d7;
            border-radius: 8px;
            padding: 12px;
            margin: 12px 0;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 13px;
            color: #1d1d1f;
            word-break: break-all;
            line-height: 1.3;
        }
        
        .form-group {
            margin: 16px 0;
        }
        
        .form-label {
            display: block;
            font-size: 15px;
            font-weight: 500;
            color: #1d1d1f;
            margin-bottom: 6px;
        }
        
        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid #d2d2d7;
            border-radius: 8px;
            font-size: 15px;
            background: #ffffff;
            color: #1d1d1f;
            transition: border-color 0.15s ease;
        }
        
        .form-input:focus {
            outline: none;
            border-color: #007aff;
        }
        
        .form-input::placeholder {
            color: #a1a1a6;
        }
        
        .btn {
            display: inline-block;
            width: 100%;
            padding: 12px 20px;
            background: #1d1d1f;
            color: #ffffff;
            text-decoration: none;
            font-size: 15px;
            font-weight: 500;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: background-color 0.15s ease;
            text-align: center;
        }
        
        .btn:hover {
            background: #424245;
        }
        
        .btn:disabled {
            background: #d2d2d7;
            color: #a1a1a6;
            cursor: not-allowed;
        }
        
        .btn-secondary {
            background: #f5f5f7;
            color: #1d1d1f;
            border: 1px solid #d2d2d7;
        }
        
        .btn-secondary:hover {
            background: #e5e5e7;
        }
        
        .btn-small {
            padding: 8px 16px;
            font-size: 14px;
            width: auto;
            display: inline-block;
        }
        
        .btn-test {
            background: #007aff;
            margin-left: 8px;
        }
        
        .btn-test:hover {
            background: #0056cc;
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 16px;
            color: #6e6e73;
            font-size: 15px;
        }
        
        .loading-spinner {
            width: 16px;
            height: 16px;
            border: 2px solid #d2d2d7;
            border-top: 2px solid #1d1d1f;
            border-radius: 50%;
            display: inline-block;
            animation: spin 1s linear infinite;
            margin-right: 8px;
            vertical-align: middle;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .result {
            margin-top: 16px;
            padding: 16px;
            border-radius: 8px;
            display: none;
        }
        
        .result.success {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            color: #166534;
        }
        
        .result.error {
            background: #fef2f2;
            border: 1px solid #fecaca;
            color: #dc2626;
        }
        
        .result h4 {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        
        .api-key-section {
            margin-top: 16px;
            padding: 16px;
            background: #f8f9fa;
            border-radius: 8px;
            border: 1px solid #e5e5e7;
        }
        
        .api-key-label {
            font-weight: 600;
            margin-bottom: 8px;
            color: #1d1d1f;
            font-size: 14px;
        }
        
        .api-key-box {
            background: #ffffff;
            border: 1px solid #d2d2d7;
            border-radius: 6px;
            padding: 12px;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 12px;
            word-break: break-all;
            color: #1d1d1f;
            margin-bottom: 8px;
        }
        
        .copy-btn {
            background: #007aff;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
        }
        
        .copy-btn:hover {
            background: #0056cc;
        }
        
        .success-message {
            margin-top: 16px;
            padding: 16px;
            background: #f0fdf4;
            border-radius: 8px;
            border: 1px solid #bbf7d0;
        }
        
        .success-title {
            font-weight: 600;
            color: #166534;
            margin-bottom: 6px;
            font-size: 14px;
        }
        
        .success-content {
            color: #166534;
            line-height: 1.4;
            font-size: 14px;
        }
        
        .success-content code {
            background: #ffffff;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 12px;
            border: 1px solid #bbf7d0;
        }
        
        .info-section {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 16px;
            margin-top: 16px;
            border: 1px solid #e5e5e7;
        }
        
        .info-title {
            font-size: 16px;
            font-weight: 600;
            color: #1d1d1f;
            margin-bottom: 12px;
        }
        
        .models-grid {
            display: grid;
            gap: 8px;
            margin-top: 12px;
        }
        
        .model-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: #ffffff;
            border: 1px solid #e5e5e7;
            border-radius: 6px;
        }
        
        .model-name {
            font-weight: 500;
            color: #1d1d1f;
            font-size: 14px;
        }
        
        .model-provider {
            font-size: 12px;
            color: #6e6e73;
        }
        
        .input-row {
            display: flex;
            gap: 8px;
            align-items: stretch;
        }
        
        .input-row .form-input {
            flex: 1;
        }
        
        .input-row .btn {
            height: auto;
            min-height: 44px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 16px 12px;
            }
            
            .header h1 {
                font-size: 28px;
            }
            
            .header p {
                font-size: 16px;
            }
            
            .section {
                padding: 16px;
            }
            
            .input-row {
                flex-direction: column;
                gap: 8px;
            }
            
            .btn-small {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Highlight 2 API</h1>
        </div>
        
        <div class="info-section">
            <div class="info-title">支持的模型</div>
            <div id="modelsList">
                <div style="text-align: center; color: #6e6e73; padding: 20px;">
                    请先获取 API Key 以查看可用模型
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">
                <span class="step-number">1</span>
                API Key 有效性检测
            </div>
            <div class="section-content">
                您可以使用现有的 API Key，或者通过登录生成新的 API Key：
            </div>
            
            <div class="form-group">
                <label class="form-label" for="apiKeyInput">API Key</label>
                <div class="input-row">
                    <input 
                        type="text" 
                        id="apiKeyInput" 
                        class="form-input"
                        placeholder="粘贴您的 API Key 或点击下方生成新的"
                    />
                    <button class="btn btn-small btn-test" onclick="testApiKey()">
                        测试并获取可用模型
                    </button>
                </div>
            </div>
            
            <div class="result" id="testResult">
                <div id="testResultContent"></div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">
                <span class="step-number">2</span>
                生成新的 API Key
            </div>
            <div class="section-content">
                如果您没有 API Key，请通过登录生成：
            </div>
            <div class="url-box">
                https://chat-backend.highlightai.com/api/v1/auth/signin?screenHint=sign-in
            </div>
            <button class="btn btn-secondary" onclick="openLoginPage()">
                打开登录页面
            </button>
            
            <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 12px; margin: 12px 0; color: #856404; font-size: 14px;">
                <strong>重要提示：</strong><br>
                1. 点击上方按钮打开登录页面<br>
                2. 完成登录后，浏览器会跳转到新页面<br>
                3. 在浏览器地址栏中找到类似这样的链接：<br>
                <code style="background: #fff; padding: 2px 4px; border-radius: 3px;">https://highlightai.com/deeplink?code=01CKIO2YTC359TRVJ1QVNQP21A</code><br>
                4. 复制 <strong>code=</strong> 后面的值（如：01CKIO2YTC359TRVJ1QVNQP21A）<br>
                5. 粘贴到下方输入框中
            </div>
            
            <div class="form-group">
                <label class="form-label" for="codeInput">授权代码（浏览器地址栏中 code= 后面的值）</label>
                <input 
                    type="text" 
                    id="codeInput" 
                    class="form-input"
                    placeholder="例如：01CKIO2YTC359TRVJ1QVNQP21A"
                />
            </div>
            
            <button class="btn" onclick="login()" id="loginBtn">
                生成 API Key
            </button>
            
            <div class="loading" id="loading">
                <span class="loading-spinner"></span>
                正在处理...
            </div>
        </div>
        
        <div class="result" id="result">
            <div id="resultContent"></div>
        </div>
        
        <div class="info-section">
            <div class="info-title">API 端点</div>
            <div style="font-size: 14px; color: #6e6e73; line-height: 1.5;">
                <strong>模型列表:</strong> GET /v1/models<br>
                <strong>请求聊天:</strong> POST /v1/chat/completions<br>
            </div>
        </div>
        
        <div style="text-align: center; margin-top: 40px; padding: 20px; border-top: 1px solid #e5e5e7;">
            <div style="color: #6e6e73; font-size: 14px; margin-bottom: 8px;">
                项目开源 · 由 <strong>三文鱼</strong> 开发
            </div>
            <div style="margin-bottom: 12px;">
                <a href="https://linux.do/u/462642146/summary" target="_blank" style="color: #007aff; text-decoration: none; font-size: 14px;">
                    🐟 Linux DO @三文鱼
                </a>
            </div>
            <div style="color: #a1a1a6; font-size: 12px;">
                感谢使用 Highlight 2 API 代理服务
            </div>
        </div>
    </div>

    <script>
        function openLoginPage() {
            window.open('https://chat-backend.highlightai.com/api/v1/auth/signin?screenHint=sign-in', '_blank');
        }
        
        async function login() {
            const codeInput = document.getElementById('codeInput');
            const loginBtn = document.getElementById('loginBtn');
            const loading = document.getElementById('loading');
            const result = document.getElementById('result');
            const resultContent = document.getElementById('resultContent');
            
            const code = codeInput.value.trim();
            if (!code) {
                showResult('error', '<h4>错误</h4><p>请输入授权代码</p>');
                return;
            }
            
            // 显示加载状态
            loginBtn.disabled = true;
            loading.style.display = 'block';
            result.style.display = 'none';
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ code })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // 登录成功，生成 API Key
                    const apiKey = btoa(JSON.stringify(data));
                    showResult('success', \`
                        <h4>登录成功</h4>
                        <p><strong>用户：</strong>\${data.email}</p>
                        <p><strong>用户 ID：</strong>\${data.user_id}</p>
                        
                        <div class="api-key-section">
                            <div class="api-key-label">您的 API Key</div>
                            <div class="api-key-box" id="apiKeyText">\${apiKey}</div>
                            <button class="copy-btn" onclick="copyApiKey()">复制 API Key</button>
                        </div>
                        
                        <div class="success-message">
                            <div class="success-title">设置完成</div>
                            <div class="success-content">
                                您现在可以使用此 API Key 调用 OpenAI 兼容的接口。<br>
                                请在 Authorization header 中添加：<br>
                                <code>Authorization: Bearer YOUR_API_KEY</code>
                            </div>
                        </div>
                    \`);
                    
                    // 自动加载模型列表
                    await loadModels(apiKey);
                } else {
                    showResult('error', \`<h4>登录失败</h4><p>\${data.error}</p>\`);
                }
            } catch (error) {
                showResult('error', \`<h4>请求失败</h4><p>\${error.message}</p>\`);
            } finally {
                loginBtn.disabled = false;
                loading.style.display = 'none';
            }
        }
        
        function showResult(type, content) {
            const result = document.getElementById('result');
            const resultContent = document.getElementById('resultContent');
            
            result.className = \`result \${type}\`;
            resultContent.innerHTML = content;
            result.style.display = 'block';
            
            // 平滑滚动到结果区域
            result.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
        
        function copyApiKey() {
            const apiKeyText = document.getElementById('apiKeyText').textContent;
            navigator.clipboard.writeText(apiKeyText).then(() => {
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = '已复制';
                setTimeout(() => {
                    btn.textContent = originalText;
                }, 2000);
            }).catch(err => {
                console.error('复制失败:', err);
                // 备用方案：选中文本
                const selection = window.getSelection();
                const range = document.createRange();
                range.selectNodeContents(document.getElementById('apiKeyText'));
                selection.removeAllRanges();
                selection.addRange(range);
            });
        }
        
        async function testApiKey() {
            const apiKeyInput = document.getElementById('apiKeyInput');
            const testResult = document.getElementById('testResult');
            const testResultContent = document.getElementById('testResultContent');
            
            const apiKey = apiKeyInput.value.trim();
            if (!apiKey) {
                showTestResult('error', '<h4>错误</h4><p>请先输入 API Key</p>');
                return;
            }
            
            try {
                const response = await fetch('/v1/models', {
                    headers: {
                        'Authorization': \`Bearer \${apiKey}\`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    showTestResult('success', \`
                        <h4>API Key 有效</h4>
                        <p>成功获取到 \${data.data.length} 个可用模型</p>
                    \`);
                    
                    // 自动显示模型列表
                    displayModels(data.data);
                } else {
                    const errorData = await response.json();
                    showTestResult('error', \`<h4>API Key 无效</h4><p>\${errorData.error || '验证失败'}</p>\`);
                }
            } catch (error) {
                showTestResult('error', \`<h4>测试失败</h4><p>\${error.message}</p>\`);
            }
        }
        
        function showTestResult(type, content) {
            const testResult = document.getElementById('testResult');
            const testResultContent = document.getElementById('testResultContent');
            
            testResult.className = \`result \${type}\`;
            testResultContent.innerHTML = content;
            testResult.style.display = 'block';
        }
        
        async function loadModels(apiKey) {
            const modelsList = document.getElementById('modelsList');
            
            // 显示加载状态
            modelsList.innerHTML = \`
                <div style="text-align: center; color: #6e6e73; padding: 16px;">
                    <span class="loading-spinner" style="margin-right: 8px;"></span>
                    正在加载模型列表...
                </div>
            \`;
            
            try {
                const response = await fetch('/v1/models', {
                    headers: {
                        'Authorization': \`Bearer \${apiKey}\`
                    }
                });
                
                if (response.ok) {
                    const data = await response.json();
                    displayModels(data.data);
                } else {
                    modelsList.innerHTML = \`
                        <div style="text-align: center; color: #dc2626; padding: 16px;">
                            加载失败，请检查 API Key
                        </div>
                    \`;
                }
            } catch (error) {
                modelsList.innerHTML = \`
                    <div style="text-align: center; color: #dc2626; padding: 16px;">
                        网络错误: \${error.message}
                    </div>
                \`;
            }
        }
        
        function displayModels(models) {
            const modelsList = document.getElementById('modelsList');
            
            if (!models || models.length === 0) {
                modelsList.innerHTML = \`
                    <div style="text-align: center; color: #6e6e73; padding: 16px;">
                        未找到可用模型
                    </div>
                \`;
                return;
            }
            
            // 按提供商分组模型
            const modelsByProvider = models.reduce((acc, model) => {
                const provider = model.owned_by || 'Unknown';
                if (!acc[provider]) acc[provider] = [];
                acc[provider].push(model);
                return acc;
            }, {});
            
            let html = '';
            for (const [provider, providerModels] of Object.entries(modelsByProvider)) {
                html += \`
                    <div style="margin-bottom: 16px;">
                        <div style="font-weight: 600; color: #1d1d1f; margin-bottom: 8px; font-size: 14px;">
                            \${provider} (\${providerModels.length} 个模型)
                        </div>
                        <div class="models-grid">
                \`;
                
                providerModels.forEach(model => {
                    html += \`
                        <div class="model-item">
                            <div>
                                <div class="model-name">\${model.id}</div>
                                <div class="model-provider">\${provider}</div>
                            </div>
                            <button onclick="copyModelName('\${model.id}')" class="btn btn-small copy-btn">
                                复制
                            </button>
                        </div>
                    \`;
                });
                
                html += \`
                        </div>
                    </div>
                \`;
            }
            
            modelsList.innerHTML = html;
        }
        
        function copyModelName(modelName) {
            navigator.clipboard.writeText(modelName).then(() => {
                // 临时显示复制成功的反馈
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = '已复制';
                btn.style.background = '#bbf7d0';
                btn.style.color = '#166534';
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.style.background = '#007aff';
                    btn.style.color = 'white';
                }, 1500);
            }).catch(err => {
                console.error('复制失败:', err);
            });
        }
        
        // 页面加载时检查是否有API Key
        document.addEventListener('DOMContentLoaded', function() {
            const apiKeyInput = document.getElementById('apiKeyInput');
            
            // 监听API Key输入变化
            apiKeyInput.addEventListener('input', function() {
                const apiKey = this.value.trim();
                if (apiKey) {
                    // 自动加载模型列表
                    loadModels(apiKey);
                } else {
                    const modelsList = document.getElementById('modelsList');
                    modelsList.innerHTML = \`
                        <div style="text-align: center; color: #6e6e73; padding: 20px;">
                            请先获取 API Key 以查看可用模型
                        </div>
                    \`;
                }
            });
            
            // 回车键提交
            document.getElementById('codeInput').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    login();
                }
            });
            
            document.getElementById('apiKeyInput').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    testApiKey();
                }
            });
        });
    </script>
</body>
</html>
    `;
    
    return new Response(html, { 
      headers: { 
        "Content-Type": "text/html; charset=utf-8",
        ...getCorsHeaders()
      }
    });
  }
  
  // 健康检查
  if (path === "/health") {
    return new Response(JSON.stringify({
      status: "healthy",
      timestamp: Math.floor(Date.now() / 1000)
    }), {
      headers: { 
        "Content-Type": "application/json",
        ...getCorsHeaders()
      }
    });
  }
  
  // 登录端点
  if (path === "/login" && request.method === "POST") {
    try {
      const body = await request.json();
      const code = body.code;
      if (!code) {
        return new Response(JSON.stringify({ error: "Missing code parameter" }), {
          status: 400,
          headers: { 
            "Content-Type": "application/json",
            ...getCorsHeaders()
          }
        });
      }
      
      const userInfo = await login(code);
      return new Response(JSON.stringify(userInfo), {
        headers: { 
          "Content-Type": "application/json",
          ...getCorsHeaders()
        }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 
          "Content-Type": "application/json",
          ...getCorsHeaders()
        }
      });
    }
  }
  
  // 获取Bearer token
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return new Response(JSON.stringify({ error: "Missing authorization token" }), {
      status: 401,
      headers: { 
        "Content-Type": "application/json",
        ...getCorsHeaders()
      }
    });
  }
  
  const token = authHeader.substring(7);
  const userInfo = parseApiKey(token);
  if (!userInfo || !userInfo.rt) {
    return new Response(JSON.stringify({ error: "Invalid authorization token" }), {
      status: 401,
      headers: { 
        "Content-Type": "application/json",
        ...getCorsHeaders()
      }
    });
  }
  
  // 模型列表
  if (path === "/v1/models" && request.method === "GET") {
    try {
      const accessToken = await getAccessToken(userInfo.rt);
      const models = await getModels(accessToken);
      
      const modelList = Array.from(models.entries()).map(([modelName, modelInfo]) => ({
        id: modelName,
        object: "model",
        created: Math.floor(Date.now() / 1000),
        owned_by: modelInfo.provider,
      }));
      
      return new Response(JSON.stringify({
        object: "list",
        data: modelList
      }), {
        headers: { 
          "Content-Type": "application/json",
          ...getCorsHeaders()
        }
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 
          "Content-Type": "application/json",
          ...getCorsHeaders()
        }
      });
    }
  }
  
  // 聊天完成
  if (path === "/v1/chat/completions" && request.method === "POST") {
    try {
      const reqData: ChatCompletionRequest = await request.json();
      
      if (!userInfo.user_id || !userInfo.client_uuid) {
        return new Response(JSON.stringify({ error: "Invalid authorization token - missing required fields" }), {
          status: 401,
          headers: { 
            "Content-Type": "application/json",
            ...getCorsHeaders()
          }
        });
      }
      
      const accessToken = await getAccessToken(userInfo.rt);
      const models = await getModels(accessToken);
      const modelInfo = models.get(reqData.model || "gpt-4o");
      
      if (!modelInfo) {
        return new Response(JSON.stringify({ error: `Model '${reqData.model}' not found` }), {
          status: 400,
          headers: { 
            "Content-Type": "application/json",
            ...getCorsHeaders()
          }
        });
      }
      
      const prompt = formatMessagesToPrompt(reqData.messages);
      const tools = formatOpenAITools(reqData.tools);
      const identifier = await getIdentifier(userInfo.user_id, userInfo.client_uuid);
      
      const highlightData = {
        prompt: prompt,
        attachedContext: [],
        modelId: modelInfo.id,
        additionalTools: tools,
        backendPlugins: [],
        useMemory: false,
        useKnowledge: false,
        ephemeral: false,
        timezone: "Asia/Hong_Kong",
      };
      
      const headers = getHighlightHeaders(accessToken, identifier);
      
      if (reqData.stream) {
        // 流式响应
        const readable = new ReadableStream({
          async start(controller) {
            try {
              const response = await fetch(`${HIGHLIGHT_BASE_URL}/api/v1/chat`, {
                method: 'POST',
                headers: headers,
                body: JSON.stringify(highlightData),
              });
              
              if (!response.ok) {
                controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify({
                  error: { message: `Highlight API returned status code ${response.status}`, type: "api_error" }
                })}\n\n`));
                controller.close();
                return;
              }
              
              const responseId = `chatcmpl-${crypto.randomUUID()}`;
              const created = Math.floor(Date.now() / 1000);
              
              // 发送初始消息
              const initialChunk = {
                id: responseId,
                object: "chat.completion.chunk",
                created: created,
                model: reqData.model || "gpt-4o",
                choices: [{
                  index: 0,
                  delta: { role: "assistant" },
                  finish_reason: null,
                }],
              };
              controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(initialChunk)}\n\n`));
              
              const reader = response.body?.getReader();
              if (!reader) return;
              
              let buffer = "";
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                
                buffer += new TextDecoder().decode(value);
                
                while (buffer.includes("\n")) {
                  const lineEnd = buffer.indexOf("\n");
                  const line = buffer.substring(0, lineEnd);
                  buffer = buffer.substring(lineEnd + 1);
                  
                  if (line.startsWith("data: ")) {
                    const data = line.substring(6).trim();
                    if (data) {
                      try {
                        const eventData = JSON.parse(data);
                        if (eventData.type === "text") {
                          const content = eventData.content || "";
                          if (content) {
                            const chunkData = {
                              id: responseId,
                              object: "chat.completion.chunk",
                              created: created,
                              model: reqData.model || "gpt-4o",
                              choices: [{
                                index: 0,
                                delta: { content: content },
                                finish_reason: null,
                              }],
                            };
                            controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(chunkData)}\n\n`));
                          }
                        }
                      } catch {
                        // 忽略无效的JSON数据
                      }
                    }
                  }
                }
              }
              
              // 发送完成消息
              const finalChunk = {
                id: responseId,
                object: "chat.completion.chunk",
                created: created,
                model: reqData.model || "gpt-4o",
                choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
              };
              controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(finalChunk)}\n\n`));
              controller.enqueue(new TextEncoder().encode("data: [DONE]\n\n"));
              controller.close();
            } catch (error) {
              controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify({
                error: { message: error.message, type: "server_error" }
              })}\n\n`));
              controller.close();
            }
          }
        });
        
        return new Response(readable, {
          headers: {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            ...getCorsHeaders()
          },
        });
      } else {
        // 非流式响应
        const response = await fetch(`${HIGHLIGHT_BASE_URL}/api/v1/chat`, {
          method: 'POST',
          headers: headers,
          body: JSON.stringify(highlightData),
        });
        
        if (!response.ok) {
          return new Response(JSON.stringify({
            error: { message: `Highlight API returned status code ${response.status}`, type: "api_error" }
          }), {
            status: response.status,
            headers: { 
              "Content-Type": "application/json",
              ...getCorsHeaders()
            }
          });
        }
        
        let fullResponse = "";
        const reader = response.body?.getReader();
        if (reader) {
          let buffer = "";
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            
            buffer += new TextDecoder().decode(value);
            
            while (buffer.includes("\n")) {
              const lineEnd = buffer.indexOf("\n");
              const line = buffer.substring(0, lineEnd);
              buffer = buffer.substring(lineEnd + 1);
              
              if (line.startsWith("data: ")) {
                const data = line.substring(6).trim();
                if (data) {
                  try {
                    const eventData = JSON.parse(data);
                    if (eventData.type === "text") {
                      fullResponse += eventData.content || "";
                    }
                  } catch {
                    // 忽略无效的JSON数据
                  }
                }
              }
            }
          }
        }
        
        const responseId = `chatcmpl-${crypto.randomUUID()}`;
        const responseData = {
          id: responseId,
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: reqData.model || "gpt-4o",
          choices: [{
            index: 0,
            message: { role: "assistant", content: fullResponse },
            finish_reason: "stop",
          }],
          usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
        };
        
        return new Response(JSON.stringify(responseData), {
          headers: { 
            "Content-Type": "application/json",
            ...getCorsHeaders()
          }
        });
      }
    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { 
          "Content-Type": "application/json",
          ...getCorsHeaders()
        }
      });
    }
  }
  
  return new Response("Not Found", { 
    status: 404,
    headers: getCorsHeaders()
  });
}

// 主函数
async function main() {
  // 检查是否有命令行参数用于登录
  const args = globalThis.Deno?.args || [];
  if (args.length > 0 && args[0] === "login") {
    if (args.length < 2) {
      console.log("使用方法: deno run --allow-net --allow-env highlight-api-deno.ts login <code>");
      console.log("浏览器打开: https://chat-backend.highlightai.com/api/v1/auth/signin?screenHint=sign-in");
      console.log("完成登录后复制 code 参数值");
      globalThis.Deno?.exit(1);
      return;
    }
    
    const code = args[1];
    try {
      await login(code);
    } catch (error) {
      console.error("登录失败:", (error as Error).message);
      globalThis.Deno?.exit(1);
      return;
    }
    return;
  }
  
  // 启动HTTP服务器
  const port = parseInt(globalThis.Deno?.env.get("PORT") || "8080");
  console.log(`Highlight AI API 代理服务器启动在端口 ${port}`);
  console.log(`健康检查: http://localhost:${port}/health`);
  console.log(`登录端点: POST http://localhost:${port}/login`);
  console.log(`模型列表: GET http://localhost:${port}/v1/models`);
  console.log(`聊天完成: POST http://localhost:${port}/v1/chat/completions`);
  
  await serve(handleRequest, { port });
}

// @ts-ignore
if (import.meta.main) {
  main();
}