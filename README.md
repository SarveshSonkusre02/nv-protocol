# 🔒 nv-protocol (`nvenv`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg)](#)
[![Security](https://img.shields.io/badge/Contextual%20Blindness-Guaranteed-success.svg)](#)

**nvenv** is a **local-first cryptographic proxy** designed to decouple raw credentials from the viewable workspace of autonomous AI software engineering agents such as **Cursor**, **Claude Code**, **Windsurf**, and **Devin**.

Instead of exposing secrets through `.env` files or shell environment variables, **nvenv** replaces them with secure cryptographic URI placeholders. During outbound network communication, the proxy dynamically substitutes placeholders with real credentials **only in volatile memory** at the OS socket boundary during TLS handshakes.

This allows applications to execute normally while keeping autonomous AI agents mathematically blind to the underlying credentials.

---

# ⚡ Quick Start

Install globally using your preferred ecosystem.

## Node.js

```bash
npm install -g nv-protocol
```

## Python

```bash
pip install nv-protocol
```

## Windows (Planned)

> **Validation Pending**

```bash
winget install SarveshSonkusre.nv-protocol
```

---

# ❓ Why nvenv?

Traditional `.env` files and shell environment variables inject plaintext secrets directly into:

- `process.env`
- `os.environ`

This exposes credentials to:

- AI coding agents
- Third-party dependencies
- Build scripts
- Prompt injection attacks
- Memory scraping

**nvenv** moves secret injection to the **network layer**, preventing untrusted processes from ever seeing the real credentials.

---

# Security Comparison

| Security Vector | Legacy `.env` / Shell Export | **nvenv** |
|-----------------|-----------------------------|-----------|
| Process Environment | ❌ Plaintext keys visible | 🛡️ Empty placeholders only |
| Prompt Injection | ❌ AI can print secrets | 🛡️ Agent never possesses secrets |
| Dependency Scraping | ❌ Malicious packages can read env | 🛡️ No credentials available |
| Authentication Scope | ❌ Every process inherits credentials | 🛡️ Injected only for authorized outbound requests |

---

# How It Works

```text
Application
Reads:

Authorization: Bearer nv://STRIPE_KEY

            │
            │ HTTP Request
            ▼

┌──────────────────────────────────┐
│      Local nvenv Proxy           │
├──────────────────────────────────┤
│ • Intercepts outbound request    │
│ • Queries encrypted vault        │
│ • Decrypts secret in memory      │
│ • Replaces placeholder           │
│ • Continues TLS connection       │
└──────────────────────────────────┘
            │
            ▼

api.stripe.com

Receives:

Authorization: Bearer sk_live_xxxxxxxxx
```

---

# Core Security Features

## 🛡️ Contextual Blindness

Your:

- source code
- `.env`
- terminal output
- logs
- shell variables

contain only placeholders such as

```text
nv://STRIPE_KEY
```

Secrets never enter the LLM context window.

---

## 🔐 Hardware-Backed Vault

On Windows, credentials are stored inside

```text
~/.nv/vault.db
```

using:

- SQLite
- Windows DPAPI encryption

Secrets are cryptographically bound to the current Windows user.

---

## 🔄 Active TLS Interception

The runtime launches a local loopback MITM proxy that:

- generates certificates dynamically
- intercepts outbound HTTPS
- swaps placeholders
- forwards requests transparently

Applications remain unaware of the substitution.

---

## 🤖 AI Agent Anti-Scraping Protection

Commands such as

```bash
nvenv get STRIPE_KEY
```

cannot be abused through:

- pipes
- redirected output
- automation

Protections include:

- `isatty()` verification
- interactive console detection
- low-level keyboard confirmation

Only a real interactive user may reveal secrets.

---

## 🔑 Git Credential Helper

nvenv integrates with Git using:

```text
credential.helper
```

GitHub Personal Access Tokens (PATs) are injected directly into Git's authentication pipeline without storing them in:

- `.gitconfig`
- environment variables
- repository files

---

# Installation

## 1. NPM Distribution

```bash
npm install -g nv-protocol
```

---

## 2. Python Distribution

```bash
pip install nv-protocol
```

---

## 3. Source Installation

Clone the repository and install locally.

```bash
pip install -e .
```

This registers the global CLI command:

```bash
nvenv
```

---

# Quickstart

## Step 1 — Initialize Vault

Create your encrypted credential database.

```bash
nvenv init
```

---

## Step 2 — Store Secrets

```bash
nvenv set STRIPE_KEY
```

The CLI securely prompts for the value and prints a placeholder.

---

## Step 3 — Replace `.env`

Instead of:

```env
STRIPE_KEY=sk_live_xxxxxxxxx
DATABASE_URL=postgres://...
```

Use:

```env
STRIPE_KEY=nv://STRIPE_KEY
DATABASE_URL=nv://DATABASE_URL
```

---

## Step 4 — Run Through nvenv

Instead of launching your application directly, wrap it.

### Node.js

```bash
nvenv run -- npm run dev
```

### Python

```bash
nvenv run -- python main.py
```

### Curl

```bash
nvenv run -- curl \
  -H "Authorization: Bearer nv://STRIPE_KEY" \
  https://httpbin.org/headers
```

Applications receive real credentials transparently while every visible environment still contains only placeholders.

---

# Git Integration

Store your GitHub Personal Access Token.

```bash
nvenv set GITHUB_TOKEN
```

Configure Git.

```bash
git config --local credential.helper "!nvenv git-helper"
```

Git authentication now occurs using credentials retrieved directly from the secure vault.

No tokens appear inside:

- repository files
- shell history
- environment variables

---

# Verification

Run the internal test suite.

```bash
python test_nv.py
```

Tests include:

- ✅ Windows DPAPI encryption
- ✅ Vault CRUD operations
- ✅ Socket payload replacement
- ✅ HTTP interception
- ✅ Placeholder substitution
- ✅ End-to-end runtime verification

---

# Example Workflow

```text
Developer

│

├── Stores API Key
│      │
│      ▼
│   nvenv set STRIPE_KEY
│
├── .env
│      │
│      ▼
│ STRIPE_KEY=nv://STRIPE_KEY
│
├── Launch
│      │
│      ▼
│ nvenv run -- npm run dev
│
└──────────────► Local Proxy
                    │
                    ▼
           Placeholder Replacement
                    │
                    ▼
             External API Service
```

---

# Philosophy

Traditional secret managers focus on protecting secrets **at rest**.

**nvenv** focuses on protecting secrets **during execution**, ensuring autonomous AI systems, third-party packages, and prompt injection attacks never gain access to plaintext credentials while applications continue to operate normally.

---

# License

Released under the **MIT License**.