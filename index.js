// index.js

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { method } = request;

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-api-key, x-bootstrap-secret, x-reset-password",
    };

    if (method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // 1. Resolve the current active key using a pointer
    const currentKeyName = await env.GLITCHPROTECT_KV.get("LATEST_KEY_NAME");
    const storedKey = currentKeyName ? await env.GLITCHPROTECT_KV.get(currentKeyName) : null;
    
    const BOOTSTRAP_SECRET = env.BOOTSTRAP_SECRET;
    const RESET_PASSWORD = env.RESET_PASSWORD;

    try {
      // --- PUBLIC / HEALTH ---
      if (method === "GET" && url.pathname === "/") {
        return new Response("GlitchProtect Worker is running.", {
          headers: { ...corsHeaders, "Content-Type": "text/plain; charset=utf-8" }
        });
      }

      // --- READ ACTIONS (GET) ---
      if (method === "GET") {
        // Validate API Key for all GET routes (except root)
        const auth = authorizeRequest(request, url, storedKey);
        if (!auth.ok) return new Response(auth.message, { status: 401, headers: corsHeaders });

        if (url.pathname === "/generate") {
          const input = url.searchParams.get("input") || "default";
          const result = await masterChaoticUnicode32(input);
          return new Response(result, { headers: corsHeaders });
        }

        if (url.pathname === "/hash") {
          const hex = url.searchParams.get("hex");
          if (!hex) return new Response("Missing 'hex'", { status: 400, headers: corsHeaders });
          const result = await hashHex(hex);
          return new Response(result, { headers: corsHeaders });
        }
      }

      // --- WRITE ACTIONS (POST) ---
      if (method === "POST") {
        // GENERATE NEW API KEY
        if (url.pathname === "/apikey") {
          // Pass storedKey to allow rotation if one exists, or fallback to bootstrap
          const auth = authorizeApiKeyIssue(request, url, storedKey, BOOTSTRAP_SECRET);
          if (!auth.ok) return new Response(auth.message, { status: 401, headers: corsHeaders });

          const newKeyID = `KEY_${crypto.randomUUID()}`;
          const raw = apiKeyChaoticUnicode();
          const safe = base64EncodeUnicode(raw);

          // Update KV with the new randomized key name and update the pointer
          await env.GLITCHPROTECT_KV.put(newKeyID, safe);
          await env.GLITCHPROTECT_KV.put("LATEST_KEY_NAME", newKeyID);

          // Cleanup old key in the background
          if (currentKeyName) ctx.waitUntil(env.GLITCHPROTECT_KV.delete(currentKeyName));

          return new Response(safe, { headers: corsHeaders });
        }

        // RESET SYSTEM
        if (url.pathname === "/reset") {
          const provided = request.headers.get("x-reset-password") || url.searchParams.get("override");
          if (!RESET_PASSWORD || provided !== RESET_PASSWORD) {
            return new Response("Unauthorized reset", { status: 401, headers: corsHeaders });
          }
          if (currentKeyName) await env.GLITCHPROTECT_KV.delete(currentKeyName);
          await env.GLITCHPROTECT_KV.delete("LATEST_KEY_NAME");
          return new Response("System Reset. Use Bootstrap Secret to generate new key.", { headers: corsHeaders });
        }
      }

      return new Response("Not Found", { status: 404, headers: corsHeaders });

    } catch (err) {
      return new Response(err.message, { status: 500, headers: corsHeaders });
    }
  }
};

/**
 * Validates the API key for general usage
 */
function authorizeRequest(request, url, storedKey) {
  if (!storedKey) return { ok: false, message: "System Locked: No API Key generated." };
  const provided = request.headers.get("x-api-key") || url.searchParams.get("key");
  return (provided === storedKey) ? { ok: true } : { ok: false, message: "Invalid API Key" };
}

/**
 * Validates credentials specifically for issuing/rotating keys
 */
function authorizeApiKeyIssue(request, url, storedKey, bootstrapSecret) {
  const providedKey = request.headers.get("x-api-key") || url.searchParams.get("key");
  const providedBootstrap = request.headers.get("x-bootstrap-secret") || url.searchParams.get("bootstrap");

  // If a key exists, you must provide it to rotate to a new one
  if (storedKey) {
    return (providedKey === storedKey) ? { ok: true } : { ok: false, message: "Active key required for rotation" };
  }

  // If no key exists (First run or post-reset), use bootstrap
  if (!bootstrapSecret || providedBootstrap !== bootstrapSecret) {
    return { ok: false, message: "Provide valid Bootstrap Secret to initialize" };
  }
  return { ok: true };
}

// --- CRYPTO UTILS ---

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
  const bytes = new Uint8Array(hexString.match(/.{1,2}/g).map(b => parseInt(b, 16)));
  const hashBuffer = await crypto.subtle.digest("SHA-512", bytes);
  return Array.from(new Uint8Array(hashBuffer), b => b.toString(16).padStart(2, "0")).join("");
}

function bytesToChaoticUnicode(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 4) {
    const code = ((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]) >>> 0;
    const safe = code % 0x10FFFF;
    if (safe >= 0xD800 && safe <= 0xDFFF) {
      out += String.fromCodePoint(safe + 0x1000); 
    } else {
      out += String.fromCodePoint(safe);
    }
  }
  return out;
}

function base64EncodeUnicode(str) {
  const bytes = new TextEncoder().encode(str);
  let binString = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binString += String.fromCharCode(bytes[i]);
  }
  return btoa(binString);
}
