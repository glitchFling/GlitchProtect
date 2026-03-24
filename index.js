// index.js

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { method } = request;

    // CORS headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-api-key",
    };

    // Handle OPTIONS preflight
    if (method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // 🔐 KV API KEY CHECK
    if (!(await validateApiKey(request, env))) {
      return new Response("Unauthorized", { status: 401, headers: corsHeaders });
    }

    // Only allow GET
    if (method !== "GET") {
      return new Response("Method Not Allowed", { status: 405, headers: corsHeaders });
    }

    try {
      let result = "";

      if (url.pathname === "/generate") {
        const input = url.searchParams.get("input") || "default";
        result = await masterChaoticUnicode32(input);
      }

      else if (url.pathname === "/apikey") {
        // 🔥 Generate new key
        const newKey = apiKeyChaoticUnicode();

        // 🔥 Save to KV
        await env.GLITCHPROTECT_KV.put("API_KEY", newKey);

        result = newKey;
      }

      else if (url.pathname === "/hash") {
        const hex = url.searchParams.get("hex");
        if (!hex) {
          return new Response("Missing 'hex' param", {
            status: 400,
            headers: corsHeaders
          });
        }
        result = await hashHex(hex);
      }

      else {
        return new Response("Not Found", { status: 404, headers: corsHeaders });
      }

      return new Response(result, {
        headers: {
          ...corsHeaders,
          "Content-Type": "text/plain; charset=utf-8"
        }
      });

    } catch (err) {
      return new Response(err.message, {
        status: 500,
        headers: corsHeaders
      });
    }
  }
};

/**
 * KV API Key Validator
 */
async function validateApiKey(request, env) {
  const provided = request.headers.get("x-api-key");
  if (!provided) return false;

  const stored = await env.GLITCHPROTECT_KV.get("API_KEY");
  if (!stored) return false;

  return provided === stored;
}

/**
 * Core Logic
 */

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
  const bytes = hexToBytes(hexString);
  const hashBuffer = await crypto.subtle.digest("SHA-512", bytes);
  return bytesToHex(new Uint8Array(hashBuffer));
}

/**
 * Helpers
 */

function bytesToChaoticUnicode(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 4) {
    const code =
      (bytes[i] << 24) |
      (bytes[i + 1] << 16) |
      (bytes[i + 2] << 8) |
      bytes[i + 3];

    const safe = code & 0x10FFFF;

    // Avoid surrogate range
    if (safe >= 0xD800 && safe <= 0xDFFF) {
      out += String.fromCodePoint(safe ^ 0x100);
    } else {
      out += String.fromCodePoint(safe);
    }
  }
  return out;
}

function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return arr;
}

function bytesToHex(bytes) {
  return [...bytes]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}
