# 🔐 CipherVault — AES-256 File Encryption Tool

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Encryption](https://img.shields.io/badge/Encryption-AES--256--CTR-red)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen)

A command-line file encryption tool using **AES-256-CTR** encryption with **PBKDF2-HMAC-SHA256** key derivation and **HMAC-SHA256** integrity verification. Encrypts any file type — documents, images, databases, configs. Zero external dependencies.

## Features
- 🔒 AES-256-CTR encryption (stream cipher — works on any file size)
- 🔑 PBKDF2-HMAC-SHA256 key derivation (200,000 iterations — brute-force resistant)
- ✅ HMAC-SHA256 integrity check (detects tampering or wrong password)
- 🛡️ Encrypt-then-MAC pattern (industry standard)
- #️⃣ Multi-algorithm file hashing (MD5, SHA-1, SHA-256, SHA-512)
- 🎲 Cryptographically secure key generator
- 📄 HTML audit log of all operations
- ⚡ Zero dependencies — pure Python standard library

## Usage
```bash
# Encrypt a file (prompts for password)
python ciphervault.py encrypt secret.txt

# Decrypt
python ciphervault.py decrypt secret.txt.vault

# Hash a file (integrity verification)
python ciphervault.py hash document.pdf

# Generate a secure random key
python ciphervault.py keygen
```

## Encrypted File Format
```
CVLT | V | SALT(32B) | IV(16B) | HMAC(32B) | CIPHERTEXT
```
- `CVLT` — magic bytes (file identifier)
- `SALT` — 32 random bytes for key derivation
- `IV`   — 16 random bytes (unique per encryption)
- `HMAC` — 32-byte integrity tag (SHA-256)

## Cryptography Concepts Used
| Component | Implementation |
|-----------|---------------|
| Encryption | AES-256-CTR (stream mode) |
| Key Derivation | PBKDF2-HMAC-SHA256, 200K iterations |
| Integrity | HMAC-SHA256 (Encrypt-then-MAC) |
| Randomness | `os.urandom()` (CSPRNG) |
| Comparison | `hmac.compare_digest()` (timing-safe) |

## Project Structure
```
CipherVault/
├── ciphervault.py      # CLI (encrypt / decrypt / hash / keygen)
├── core/
│   ├── crypto.py       # Encryption engine (AES-256-CTR + HMAC)
│   └── reporter.py     # HTML audit log generator
└── reports/            # Audit logs saved here
```

## Author
**Daksh Shah** — B.Tech Cybersecurity, SAKEC Mumbai  
[![LinkedIn](https://img.shields.io/badge/LinkedIn-daksh--shah9135-blue)](https://linkedin.com/in/daksh-shah9135)

MIT License — For educational and authorized use only.
