# 🌌 UniMaster Worker

![Static Badge](https://img.shields.io/badge/Passing-brightgreen?logo=Cloudflare&logoColor=FFFFFF&label=Cloudflare%20Workers&labelColor=FF8C00)

A high-entropy Unicode string generator and cryptographic utility running on the edge. **UniMaster** converts standard inputs into chaotic, full-spectrum Unicode strings using the Web Crypto API.

## 🚀 Features

- **Chaotic Generation**: Maps SHA-256 hashes to the full 21-bit Unicode range (`0x10FFFF`).
- **Surrogate Safety**: Automatically handles UTF-16 surrogate pairs to prevent encoding errors.
- **Edge Native**: Built specifically for Cloudflare Workers using ES Modules.
- **CORS Enabled**: Ready to be called from any frontend application.

## 🛠 API Endpoints

### 1. Generate Chaotic String
Generates a deterministic chaotic string based on your input.
- **Endpoint:** `/generate`
- **Method:** `GET`
- **Params:** `?input=your_string`
- **Example:** `https://your-worker.workers.dev`

### 2. Random API Key
Generates a 2048-byte high-entropy random Unicode string.
- **Endpoint:** `/apikey`
- **Method:** `GET`
- **Auth:** 
  - If no API key exists yet, provide bootstrap secret via `x-bootstrap-secret` header (or `?bootstrap=`).
  - If an API key already exists, provide `x-api-key` header (or `?key=`).
- **Example:** `https://your-worker.workers.dev/apikey`

### 3. Hex to SHA-512
Hashes a hex string using SHA-512.
- **Endpoint:** `/hash`
- **Method:** `GET`
- **Params:** `?hex=abcdef1234...`

### 4. Reset API Key
Deletes the stored API key so bootstrap can run again.
- **Endpoint:** `/reset`
- **Method:** `GET`
- **Auth:** `x-reset-password` header (or `?override=`) must match `RESET_PASSWORD` env var.

## 🔐 Required Worker Secrets

Set these as Cloudflare Worker secrets:

- `BOOTSTRAP_SECRET`: required for first-time `/apikey` bootstrap when no API key is stored.
- `RESET_PASSWORD`: required for `/reset`.

## 📦 Deployment

1. **Install Wrangler**:
   ```bash
   npm install -g wrangler
