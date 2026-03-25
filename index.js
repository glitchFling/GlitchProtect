// index.js

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { method } = request;

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS", // Added POST
      "Access-Control-Allow-Headers": "Content-Type, x-api-key, x-bootstrap-secret, x-reset-password",
    };

    if (method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const storedKey = await env.GLITCHPROTECT_KV.get("API_KEY");
    const RESET_PASSWORD = env.RESET_PASSWORD;
    const BOOTSTRAP_SECRET = env.BOOTSTRAP_SECRET;

    try {
      // 1. PUBLIC INFO / HEALTH CHECK
      if (method === "GET" && url.pathname === "/") {
        return new Response("GlitchProtect Worker is running.", {
          headers: { ...corsHeaders, "Content-Type": "text/plain; charset=utf-8" }
        });
      }

      // 2. READ-ONLY ACTIONS (GET)
      if (method === "GET") {
        if (url.pathname === "/generate") {
          const input = url.searchParams.get("input") || "default";
          const result = await masterChaoticUnicode32(input);
          return new Response(result, { headers: corsHeaders });
        }

        if (url.pathname === "/hash") {
          const hex = url.searchParams.get("hex");
          if (!hex) return new Response("Missing 'hex' param", { status: 400, headers: corsHeaders });
          const result = await hashHex(hex);
          return new Response(result, { headers: corsHeaders });
        }
      }

      // 3. STATE-CHANGING ACTIONS (POST)
      if (method === "POST") {
        // Generate/Update API Key
        if (url.pathname === "/apikey") {
          const auth = authorizeApiKeyIssue(request, url, storedKey, BOOTSTRAP_SECRET);
          if (!auth.ok) return new Response(auth.message, { status: 401, headers: corsHeaders });

          const raw = apiKeyChaoticUnicode();
          const safe = base64EncodeUnicode(raw);
          await env.GLITCHPROTECT_KV.put("API_KEY", safe);
          return new Response(safe, { headers: corsHeaders });
        }

        // Reset API Key
        if (url.pathname === "/reset") {
          const provided = request.headers.get("x-reset-password") || url.searchParams.get("override");
          if (!RESET_PASSWORD || provided !== RESET_PASSWORD) {
            return new Response("Unauthorized reset", { status: 401, headers: corsHeaders });
          }
          await env.GLITCHPROTECT_KV.delete("API_KEY");
          return new Response("API key reset. Call /apikey again.", { headers: corsHeaders });
        }
      }

      return new Response("Not Found or Method Not Allowed", { status: 404, headers: corsHeaders });

    } catch (err) {
      return new Response(err.message, { status: 500, headers: corsHeaders });
    }
  }
};

function authorizeApiKeyIssue(request, url, storedKey, bootstrapSecret) {
  const providedApiKey = request.headers.get("x-api-key") || url.searchParams.get("key");

  if (storedKey) {
    return (providedApiKey === storedKey) ? { ok: true } : { ok: false, message: "Unauthorized" };
  }

  const providedBootstrap = request.headers.get("x-bootstrap-secret") || url.searchParams.get("bootstrap");
  if (!bootstrapSecret || providedBootstrap !== bootstrapSecret) {
    return { ok: false, message: "Unauthorized bootstrap" };
  }
  return { ok: true };
}

async function masterChaoticUnicode32(input) {
  const enc = new TextEncoder().encode(input);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", enc));
  const bytes = new Uint8Array(2048);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = hash[i % hash.length] ^ (i * 31);
  }
  return bytesToChaoticUnicode(bytes);
}

function apiKeyChaoticUnicode() {
  const bytes = new Uint8Array(2048);
  crypto.getRandomValues(bytes);
  return bytesToChaoticUnicode(bytes);
}

async function hashHex(hexString) {
  if (!/^[0-9a-fA-F]+$/.test(hexString) || hexString.length % 2 !== 0) {
    throw new Error("Invalid hex input");
  }
  const bytes = hexToBytes(hexString);
  const hashBuffer = await crypto.subtle.digest("SHA-512", bytes);
  return bytesToHex(new Uint8Array(hashBuffer));
}

function bytesToChaoticUnicode(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 4) {
    // Added >>> 0 to ensure unsigned 32-bit integer
    const code = ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
    const safe = code % 0x10FFFF; // Modulo ensures range safety

    // Avoid surrogate pairs
    if (safe >= 0xD800 && safe <= 0xDFFF) {
      out += String.fromCodePoint(safe + 0x1000); 
    } else {
      out += String.fromCodePoint(safe);
    }
  }
  return out;
}

function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

function base64EncodeUnicode(str) {
  // Reliable way to handle Unicode -> Base64 in Workers
  const bytes = new TextEncoder().encode(str);
  let binString = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binString += String.fromCharCode(bytes[i]);
  }
  return btoa(binString);
}
