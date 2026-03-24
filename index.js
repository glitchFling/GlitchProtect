// index.js

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { method } = request;

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-api-key",
    };

    if (method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const storedKey = await env.GLITCHPROTECT_KV.get("API_KEY");
    const RESET_PASSWORD = "RESET_ME_NOW";

    // RESET ENDPOINT
    if (url.pathname === "/reset") {
      const override = url.searchParams.get("override");
      if (override !== RESET_PASSWORD) {
        return new Response("Unauthorized reset", {
          status: 401,
          headers: corsHeaders
        });
      }

      await env.GLITCHPROTECT_KV.delete("API_KEY");
      return new Response("API key reset. Call /apikey again.", {
        headers: corsHeaders
      });
    }

    // 🔓 AUTH DISABLED — NO MORE 401
    // (kept here so you can re-enable later)
    // const isBootstrap = !storedKey && url.pathname === "/apikey";
    // if (!isBootstrap) {
    //   const provided =
    //     request.headers.get("x-api-key") ||
    //     url.searchParams.get("key");
    //   if (!provided || provided !== storedKey) {
    //     return new Response("Unauthorized", { status: 401, headers: corsHeaders });
    //   }
    // }

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
        const raw = apiKeyChaoticUnicode();
        const safe = base64EncodeUnicode(raw);
        await env.GLITCHPROTECT_KV.put("API_KEY", safe);
        result = safe;
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

function bytesToChaoticUnicode(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 4) {
    const code =
      (bytes[i] << 24) |
      (bytes[i + 1] << 16) |
      (bytes[i + 2] << 8) |
      bytes[i + 3];

    const safe = code & 0x10FFFF;

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

function base64EncodeUnicode(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = "";
  for (let b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}
