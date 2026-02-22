# 🔐 Message Encrypt / Decrypt

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red?style=flat-square&logo=streamlit)
![Crypto](https://img.shields.io/badge/Encryption-Fernet_AES--128--CBC-green?style=flat-square&logo=letsencrypt)
![TTL](https://img.shields.io/badge/Message_Expiry-5_Minutes-orange?style=flat-square)

Secure messaging app that encrypts and decrypts messages using **Fernet symmetric encryption** (AES-128-CBC + HMAC-SHA256). Features a **combined token** that merges the key and ciphertext into one opaque string, a **passphrase mode** requiring zero key exchange, and a hard-coded **5-minute message expiry**.

---

## 🔄 How It Works

```mermaid
flowchart TD
    A([User selects ENCRYPT]) --> B{Key mode?}
    B -->|Auto-generate| C["Fernet.generate_key\n→ random 32 bytes\n→ Base64 encode → 44-char key"]
    B -->|Custom passphrase| D["SHA-256 passphrase\n→ 32 bytes\n→ Base64 encode → 44-char key"]
    C --> E[User types plaintext message]
    D --> E
    E --> F["Fernet.encrypt\nAES-128-CBC + HMAC-SHA256\n+ timestamp embedded"]
    F --> G["Ciphertext token\ngAAAAAB..."]
    G --> H["make_combined_token\nBase64_decode key → 32 raw bytes\nBase64_decode ciphertext → N raw bytes\nConcatenate → Base64_encode"]
    H --> I(["One opaque Combined Token\nlooks like a random string"])
    I --> J{Share via?}
    J -->|Copy| K[navigator.clipboard.writeText]
    J -->|WhatsApp| L["api.whatsapp.com/send?text=token"]
```

---

## 🚀 Quick Start

```bash
git clone <repo-url>
cd message_encrypt_decrypt
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

App opens at **http://localhost:8501**

---

## 📂 Project Structure

```
message_encrypt_decrypt/
├── app.py              # Main Streamlit application
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── .streamlit/
    └── config.toml     # Dark theme config
```

---

## 🔧 Tech Stack

| Component | Technology |
|---|---|
| UI | Streamlit |
| Encryption | cryptography (Fernet — AES-128-CBC + HMAC-SHA256) |
| Key Derivation | hashlib SHA-256 |
| Sharing | WhatsApp URL scheme, navigator.clipboard |
| Language | Python 3.10+ |

---

## 🛡️ Key Features

| Feature | Description |
|---|---|
| **Auto key generation** | Random 256-bit Fernet key on Encrypt selection |
| **Passphrase mode** | SHA-256 derived key — no key ever transmitted |
| **Combined token** | Key + ciphertext merged into one Base64 blob — looks random |
| **5-minute expiry** | Hard-coded TTL on every message — cannot be changed |
| **Copy to clipboard** | `navigator.clipboard` — no external JS libs |
| **Share on WhatsApp** | Combined token pre-filled in WhatsApp |
| **Paste from WhatsApp** | Auto-detects combined token or labelled format, auto-decrypts |

---

## 📊 Security Design

| Decision | Rationale |
|---|---|
| Key sent separately from ciphertext | Sending both together lets any interceptor decrypt |
| Combined token merges them opaquely | Key boundary unknown without app — looks like noise |
| Passphrase mode eliminates key transit | Shared secret never leaves either device |
| 5-minute TTL | Limits the window an intercepted token is useful |
| HMAC-SHA256 | Any tampered bit causes decryption to fail |

---

## 👤 Author

**Seelaboyina Deekshith**

[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Deekshith06)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/deekshith030206)
[![Email](https://img.shields.io/badge/Email-D14836?style=for-the-badge&logo=gmail&logoColor=white)](mailto:seelaboyinadeekshith@gmail.com)

---

> ⭐ Star this repo if it helped you!
