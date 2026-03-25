// index.js

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const id = env.MASTER_GATE.idFromName('global-lock');
    const gate = env.MASTER_GATE.get(id);

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-api-key",
    };

    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

    try {
      // 1. Key Management (Forwarded to Durable Object)
      if (url.pathname === "/apikey" || url.pathname === "/verify") {
        const gateResponse = await gate.fetch(request);
        const body = await gateResponse.text();
        return new Response(body, { status: gateResponse.status, headers: corsHeaders });
      }

      // 2. Health Check
      if (url.pathname === "/") {
        return new Response("GlitchProtect DO (SQLite) is Active.", { headers: corsHeaders });
      }

      // 3. Protected Utility Actions
      if (url.pathname === "/generate" || url.pathname === "/hash") {
        const auth = await gate.fetch(new Request(url.origin + "/check", {
          headers: { "x-api-key": request.headers.get("x-api-key") || "" }
        }));
        
        if (auth.status !== 200) return new Response("Unauthorized", { status: 401, headers: corsHeaders });

        if (url.pathname === "/generate") {
          return new Response(await masterChaoticUnicode32(url.searchParams.get("input") || "default"), { headers: corsHeaders });
        }
        
        if (url.pathname === "/hash") {
          const hex = url.searchParams.get("hex");
          if (!hex) return new Response("Missing 'hex'", { status: 400, headers: corsHeaders });
          return new Response(await hashHex(hex), { headers: corsHeaders });
        }
      }

      return new Response("Not Found", { status: 404, headers: corsHeaders });

    } catch (err) {
      return new Response(err.message, { status: 500, headers: corsHeaders });
    }
  }
};

/**
 * THE DURABLE OBJECT CLASS (SQLite-Backed)
 */
export class MasterGate {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const providedKey = request.headers.get("x-api-key");
    const storedKey = await this.state.storage.get("MASTER_KEY");

    // Initialize Key
    if (url.pathname === "/apikey" && request.method === "POST") {
      if (storedKey) return new Response("Locked", { status: 403 });
      
      const newKey = apiKeyChaoticUnicode();
      const safe = base64EncodeUnicode(newKey);
      await this.state.storage.put("MASTER_KEY", safe);
      return new Response(safe);
    }

    // Verify AND Burn (One-time use)
    if (url.pathname === "/verify") {
      if (storedKey && providedKey === storedKey) {
        await this.state.storage.delete("MASTER_KEY");
        return new Response("VALID_AND_BURNED", { status: 200 });
      }
      return new Response("INVALID_OR_EXPIRED", { status: 401 });
    }

    // Check (Validate without burning)
    if (url.pathname === "/check") {
      return (storedKey && providedKey === storedKey) 
        ? new Response("OK", { status: 200 }) 
        : new Response("FAIL", { status: 401 });
    }

    return new Response("DO Not Found", { status: 404 });
  }
}

// --- UTILITIES ---

async function masterChaoticUnicode32(input) {
  const enc = new TextEncoder().encode(input);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", enc));
  const bytes = new Uint8Array(2048);
  for (let i = 0; i < bytes.length; i++) bytes[i] = hash[i % hash.length] ^ (i * 31);
  return bytesToChaoticUnicode(bytes);
}

function apiKeyChaoticUnicode() {
  const bytes = new Uint8Array(2048);
  crypto.getRandomValues(bytes);
  return bytesToChaoticUnicode(bytes);
}

async function hashHex(hexString) {
  if (!/^[0-9a-fA-F]+$/.test(hexString) || hexString.length % 2 !== 0) throw new Error("Invalid hex");
  const bytes = new Uint8Array(hexString.match(/.{1,2}/g).map(b => parseInt(b, 16)));
  const hashBuffer = await crypto.subtle.digest("SHA-512", bytes);
  return Array.from(new Uint8Array(hashBuffer), b => b.toString(16).padStart(2, "0")).join("");
}

function bytesToChaoticUnicode(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 4) {
    const code = ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
    const safe = code % 0x10FFFF;
    if (safe >= 0xD800 && safe <= 0xDFFF) out += String.fromCodePoint(safe + 0x1000); 
    else out += String.fromCodePoint(safe);
  }
  return out;
}

function base64EncodeUnicode(str) {
  const bytes = new TextEncoder().encode(str);
  let binString = "";
  for (let i = 0; i < bytes.byteLength; i++) binString += String.fromCharCode(bytes[i]);
  return btoa(binString);
}
