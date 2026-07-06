# nvenv (No-View Env)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg)](#)
[![Security](https://img.shields.io/badge/Contextual%20Blindness-Mathematically%20Guaranteed-success.svg)](#)

**nvenv** is a local-first cryptographic proxy tool designed to decouple raw credentials from the viewable workspace of autonomous AI software engineering agents (e.g., Cursor, Claude Code, Windsurf, Devin). 

By replacing filesystem `.env` credentials with secure cryptographic URI placeholders and substituting the actual keys dynamically at the OS socket boundary in volatile memory during TLS handshakes, **nvenv** ensures your runtime applications execute flawlessly while leaving the autonomous LLM agent mathematically blind to the underlying credentials.

---

## How It Works (The Core Mechanism)

```
[Application Process] (Reads env containing placeholder "nv://STRIPE_SECRET_KEY")
       |
       | 1. Dispatches HTTP POST packet
       |    Authorization Header: "Bearer nv://STRIPE_SECRET_KEY"
       v
[Local nvenv Proxy Loopback Engine]
       |
       | 2. Intercepts outbound TLS request via Local CA
       | 3. Queries volatile memory for the real credentials
       | 4. Substitutes "nv://STRIPE_SECRET_KEY" with "sk_live_51Nx..."
       v
[External Target API Endpoint] (e.g., api.stripe.com)
```

---

## Core Security Features

- **Contextual Blindness ($I(C_{\text{text}}; S) = 0$):** Your code files, terminal logs, and system variables contain only hollow placeholders (e.g., `nv://STRIPE_KEY`). Secrets never enter the LLM's context window.
- **Hardware-Backed Vault:** On Windows, secrets are stored in a local SQLite database (`~/.nv/vault.db`) and encrypted using the **Windows Data Protection API (DPAPI)**, binding them to your operating system user identity and TPM.
- **Active TLS Interception:** Spawns a transient, local Man-in-the-Middle (MITM) loopback proxy that signs dynamic certificates on-the-fly, swapping placeholders in request headers and payloads during execution.
- **AI Agent Anti-Scraping Defense:** Prevents AI agents from scraping plaintext keys via shell commands (e.g., `nvenv get`). It blocks decryption in piped or redirected environments (`isatty` check) and requires interactive, low-level OS keyboard confirmation (`msvcrt` console read) to print keys.
- **Git Credential Helper:** Plugs directly into Git (`credential.helper`) to intercept remote authentication commands, injecting GitHub Personal Access Tokens (PATs) at the OS socket pipe level without checking tokens into files.

---

## Installation Options

### 1. Developer Python Source Installation (Recommended for testing)
Ensure you have `pyinstaller` and `cryptography` installed:
```cmd
pip install -e .
```
This registers the global CLI script `nvenv` in your environment PATH.

### 2. NPM Distribution (Language-Agnostic JS Wrapper)
For developers using Node/NPM globally:
```cmd
npm install -g nv-protocol
```
*Note: This utilizes a global Node.js redirector script that routes requests directly to the precompiled platform-specific executable.*

### 3. Windows Package Manager (Winget)
```cmd
winget install OpenSourceSecurity.nv
```

### 4. Linux & macOS (Bash Installer)
```bash
curl -fsSL https://raw.githubusercontent.com/oss-security/nv-protocol/main/install.sh | bash
```

---

## Quickstart Guide

### Step 1: Initialize Vault
Create your secure database:
```cmd
nvenv init
```

### Step 2: Store Your Secrets
Save your API keys securely:
```cmd
nvenv set STRIPE_KEY
```
*(You will be securely prompted for the value. The CLI will output a copy-pasteable configuration line).*

### Step 3: Populate Your `.env` File
Replace the plaintext secrets in your project's `.env` with the placeholders generated:
```env
STRIPE_KEY=nv://STRIPE_KEY
DATABASE_URL=nv://DATABASE_URL
```

### Step 4: Run Your Code Wrapped in the Sandbox
Instead of booting your compiler or runtime directly, wrap the command in `nvenv run --`:
```cmd
# Node.js Example
nvenv run -- npm run dev

# Python Example
nvenv run -- python main.py

# Curl Example
nvenv run -- curl -X GET https://httpbin.org/headers -H "Authorization: Bearer nv://STRIPE_KEY"
```

The application will run with the correct keys, but the shell, output logs, and system environment table will only see `nv://STRIPE_KEY`.

---

## Git Integration Setup

Protect your repository push/pull pipelines from token scraping:
1. Save your Personal Access Token (PAT) under the name `GITHUB_TOKEN`:
   ```cmd
   nvenv set GITHUB_TOKEN
   ```
2. Enable the local Git Credential Helper for your repository:
   ```cmd
   git config --local credential.helper "!nvenv git-helper"
   ```
Now, Git will verify remote write operations by securely piping tokens from the hardware store, keeping files clean of credential details.

---

## Troubleshooting & Verification

To verify that your installation is working correctly, run the internal test suite:
```cmd
python test_nv.py
```
This tests:
1. Native Windows DPAPI encryption stability.
2. Local vault schema CRUD.
3. Socket payload replacement over mock HTTP interception streams.
