# 🔒 nv-protocol (`nvenv`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20macos%20%7C%20linux-lightgrey.svg)](#)
[![Security](https://img.shields.io/badge/Contextual%20Blindness-Guaranteed-success.svg)](#)

**nvenv** is a **local-first cryptographic proxy** designed to decouple raw credentials from the viewable workspace of autonomous AI software engineering agents such as **Cursor**, **Claude Code**, **Windsurf**, and **Devin**.

Instead of exposing secrets through traditional `.env` files or shell environment variables, **nvenv** replaces them with secure cryptographic URI placeholders (`nv://KEY_NAME`). During outbound network communication, the proxy transparently substitutes placeholders with the real credentials **only in volatile memory**, immediately before the TLS request leaves the machine.

Applications continue to work normally while autonomous AI agents remain unable to access plaintext credentials.

---

# ⚡ Quick Start

## Install Globally (Recommended)

### Node.js

```bash
npm install -g nv-protocol
```

### Python

```bash
pip install nv-protocol
```

### Windows Package Manager *(Coming Soon)*

```bash
winget install SarveshSonkusre.nv-protocol
```

Verify installation:

```bash
nvenv --help
```

---

# 📦 Installation Options

## Global Installation

Recommended if you want the `nvenv` command available everywhere.

### npm

```bash
npm install -g nv-protocol
```

### PyPI

```bash
pip install nv-protocol
```

---

## Local Project Installation (Node.js)

Install only inside the current project.

```bash
npm install nv-protocol
```

Run using:

```bash
npx nvenv --help
```

or from your package scripts.

---

## Install From Source

```bash
git clone https://github.com/SarveshSonkusre02/nv-protocol.git

cd nv-protocol

pip install -e .
```

---

# ✅ Verify Installation

Display the CLI help.

```bash
nvenv --help
```

Expected output:

```text
nvenv (No-View Env) - Context-Isolated Secret Management CLI
```

Verify installed package.

### npm

```bash
npm list -g nv-protocol
```

### PyPI

```bash
pip show nv-protocol
```

---

# ❓ Why nvenv?

Traditional secret management exposes credentials directly inside:

- `.env`
- `process.env`
- `os.environ`
- shell exports

This means secrets become visible to:

- AI coding agents
- Third-party dependencies
- Build systems
- Prompt injection attacks
- Memory scraping tools

**nvenv** shifts credential injection from the application layer to the **network layer**, ensuring applications authenticate normally while secrets never become part of the AI-visible execution context.

---

# 🔒 Security Comparison

| Security Vector | Legacy `.env` / Shell Export | **nvenv** |
|-----------------|-----------------------------|-----------|
| Process Environment | ❌ Plaintext credentials | ✅ Placeholder only |
| Prompt Injection | ❌ Secrets can be printed | ✅ AI never receives secrets |
| Dependency Scraping | ❌ Packages can read env vars | ✅ No credentials available |
| Authentication Scope | ❌ Shared with every process | ✅ Injected only into authorized outbound requests |
| Secret Lifetime | ❌ Entire process lifetime | ✅ Exists only during request execution |

---

# 🏗 Architecture

```text
Developer

        │

        ▼

Application
Reads

OPENAI_API_KEY=nv://OPENAI_API_KEY

        │

        ▼

────────────────────────────────────────────

           nvenv Proxy

• Validate destination
• Retrieve encrypted secret
• Decrypt in volatile memory
• Replace placeholder
• Forward TLS request

        │

        ▼

External API

Authorization:
Bearer sk-xxxxxxxxxxxxxxxx
```

---

# 🚀 Quick Start

## Initialize the Vault

```bash
nvenv init
```

---

## Store a Secret

```bash
nvenv set OPENAI_API_KEY
```

---

## Replace Your `.env`

Instead of:

```env
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxx
```

Use:

```env
OPENAI_API_KEY=nv://OPENAI_API_KEY
```

---

## Run Your Application

### Node.js

```bash
nvenv run -- npm run dev
```

### Python

```bash
nvenv run -- python app.py
```

---

## List Stored Secrets

```bash
nvenv list
```

---

# ⚙️ How It Works

```text
Application

Authorization:
Bearer nv://OPENAI_API_KEY

           │

           ▼

┌───────────────────────────────┐
│         nvenv Proxy           │
├───────────────────────────────┤
│ • Intercepts request          │
│ • Reads encrypted vault       │
│ • Decrypts in RAM             │
│ • Replaces placeholder        │
│ • Sends HTTPS request         │
└───────────────────────────────┘

           │

           ▼

api.openai.com

Authorization:
Bearer sk-xxxxxxxxxxxxxxxx
```

---

# 🛡 Core Security Features

## Context Isolation

Your:

- source code
- `.env`
- terminal
- logs
- shell variables

contain only placeholders.

```text
OPENAI_API_KEY=nv://OPENAI_API_KEY
```

Secrets never become visible inside an AI context window.

---

## Hardware-Backed Vault

Windows stores credentials inside:

```text
~/.nv/vault.db
```

using:

- SQLite
- Windows DPAPI encryption

Secrets are cryptographically bound to the current Windows user account.

---

## Memory-Only Secret Injection

Credentials are:

- decrypted only when needed
- never stored inside environment variables
- never written to disk
- wiped immediately after request completion

---

## HTTPS Proxy Injection

The runtime launches a local HTTPS interception proxy which:

- validates destinations
- decrypts secrets
- replaces placeholders
- forwards encrypted traffic

Applications remain unaware that substitution occurred.

---

## AI Agent Protection

Commands such as

```bash
nvenv get OPENAI_API_KEY
```

cannot be abused through:

- redirected output
- pipes
- automated execution
- non-interactive sessions

The CLI verifies that a real interactive user is present before revealing secrets.

---

## Git Credential Helper

Store your GitHub Personal Access Token.

```bash
nvenv set GITHUB_TOKEN
```

Configure Git.

```bash
git config --local credential.helper "!nvenv git-helper"
```

Git retrieves credentials directly from the encrypted vault without exposing tokens through:

- environment variables
- shell history
- repository files
- `.gitconfig`

---

# 💻 Platform Support

| Platform | Status |
|----------|--------|
| Windows | ✅ Stable |
| Linux | 🚧 In Progress |
| macOS | 🚧 In Progress |
| npm | ✅ Available |
| PyPI | ✅ Available |
| WinGet | ⏳ Pending |

---

# 🧪 Verification

Run the built-in tests.

```bash
python test_nv.py
```

Coverage includes:

- ✅ Vault CRUD
- ✅ Windows DPAPI encryption
- ✅ Placeholder substitution
- ✅ HTTPS interception
- ✅ Runtime injection
- ✅ End-to-end verification

---

# 📈 Example Workflow

```text
Developer

     │

     ▼

nvenv set OPENAI_API_KEY

     │

     ▼

Encrypted Vault

     │

     ▼

.env

OPENAI_API_KEY=nv://OPENAI_API_KEY

     │

     ▼

nvenv run -- npm run dev

     │

     ▼

Application

     │

     ▼

nvenv Proxy

     │

     ▼

Placeholder Replacement

     │

     ▼

OpenAI API
```

---

# 🎯 Philosophy

Traditional secret managers primarily protect credentials **at rest**.

**nvenv** focuses on protecting credentials **during execution**, preventing autonomous AI systems, third-party packages, and prompt injection attacks from ever accessing plaintext secrets while preserving the existing application workflow.

---

# 🗺 Roadmap

- ✅ npm Distribution
- ✅ PyPI Distribution
- ⏳ WinGet Distribution
- ⏳ Homebrew Formula
- ⏳ Native Linux Secret Backend
- ⏳ Native macOS Keychain Backend
- ⏳ Docker Integration
- ⏳ VS Code Extension

---

# 📝 Notes

### Global npm installation

```bash
npm install -g nv-protocol
```

Installs the `nvenv` command globally.

---

### Local npm installation

```bash
npm install nv-protocol
```

Installs the package only inside the current project.

Use:

```bash
npx nvenv
```

or reference it from your project's scripts.

---

### Python installation

```bash
pip install nv-protocol
```

Installs the `nvenv` command globally into the active Python environment.

---

# 📄 License

Released under the **MIT License**.
