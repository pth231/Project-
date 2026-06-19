# Secure Shopping Platform — Topic 6

**Status**: Phase 0 Demo Ready ✅ (June 19, 2026)

## Project Overview

This is a **post-quantum secure shopping platform** built with FastAPI, demonstrating real-world cryptographic applications:

- **AES-256-GCM**: Symmetric encryption for sensitive data
- **FALCON-512**: Post-quantum digital signatures (via liboqs)
- **Argon2**: Password hashing
- **JWT tokens** signed with FALCON
- **ECDHE** (future): Forward secrecy key exchange

---

## Phase 0: Skeleton Running ✅

### What's Implemented (June 19)

| Component | Status | Details |
|-----------|--------|---------|
| **requirements.txt** | ✅ Complete | FastAPI, uvicorn, PyCryptodome, liboqs, argon2-cffi, etc. |
| **crypto_utils.py** | ✅ Complete | AES encrypt/decrypt, FALCON keypair gen, sign/verify + self-test |
| **auth.py** | ✅ Complete | Argon2 hash, FALCON JWT create/verify |
| **main.py** | ✅ Complete | FastAPI app with `/register` and `/login` endpoints |
| **demo.py** | ✅ Complete | Async demo: starts server → register → login → verify JWT |

### Quick Start

```bash
# 1. Setup environment
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt

# 2. Run demo
python demo.py
```

**Expected output:**
```
=== SECURE SHOPPING PLATFORM — LIVE API DEMO ===

Step 1: User Registration
  ✓ Registration successful

Step 2: User Login & JWT Generation
  ✓ Login successful
  ✓ Message: Login successful - JWT contains FALCON signature

Step 3: JWT Structure Analysis
  ✓ JWT structure verified

Step 4: Demo Summary
  Demo Complete: 3/3 operations passed
  ✓ Secure Shop API demonstrated successfully!
```

### File Structure

```
Project_Topic6/
├── requirements.txt           # All dependencies
├── README.md                  # This file
├── main.py                    # FastAPI app (POST /register, POST /login)
├── auth.py                    # Argon2 + FALCON JWT functions
├── crypto_utils.py            # AES-256-GCM, FALCON crypto
├── demo.py                    # Live demo script (async httpx)
├── models.py                  # SQLAlchemy models (for Phase 1)
├── audit.py                   # Audit log stub (for Phase 1)
└── keys/                      # PEM keys storage (future use)
    └── .gitkeep
```

---

## API Endpoints (Phase 0)

### POST /register

Register a new user with Argon2 password hashing.

**Request:**
```json
{
  "username": "nguyen_van_a",
  "password": "secure_password_123",
  "email": "nguyenvana@secure-shop.local"
}
```

**Response:**
```json
{
  "status": "success",
  "username": "nguyen_van_a",
  "message": "Registration successful"
}
```

### POST /login

Login and receive FALCON-signed JWT token.

**Request:**
```json
{
  "username": "nguyen_van_a",
  "password": "secure_password_123"
}
```

**Response:**
```json
{
  "username": "nguyen_van_a",
  "token": "eyJhbGc...",
  "message": "Login successful - JWT contains FALCON signature"
}
```

**JWT Structure** (after decoding):
```json
{
  "alg": "FALCON-512",
  "typ": "JWT",
  "username": "nguyen_van_a",
  "email": "nguyenvana@secure-shop.local",
  "role": "customer",
  "iat": 1718904000,
  "exp": 1718907600
}
```

---

## Demo Flow (demo.py)

The demo script automates the entire API flow:

1. **Startup** → Start FastAPI server in subprocess
2. **Register** → POST /register with test user
3. **Login** → POST /login, receive FALCON-signed JWT
4. **JWT Analysis** → Decode and inspect JWT structure
5. **Summary** → Show results table status
6. **Cleanup** → Stop server cleanly

All output is shown in the terminal.

---

## Cryptographic Details

### AES-256-GCM (crypto_utils.py)

- **Key size**: 256 bits (32 bytes)
- **Nonce**: 16 random bytes
- **Mode**: Galois/Counter Mode (authenticated encryption)
- **Return format**: Dict with hex-encoded ciphertext, nonce, auth tag

**Example:**
```python
from crypto_utils import aes_encrypt, aes_decrypt
import secrets

key = secrets.token_bytes(32)
plaintext = b"Hello Secure Shop!"

# Encrypt
encrypted = aes_encrypt(plaintext, key)
# Returns: {"ciphertext": "a1b2c3...", "nonce": "d4e5f6...", "tag": "789abc..."}

# Decrypt
decrypted = aes_decrypt(
    encrypted["ciphertext"], key, 
    encrypted["nonce"], encrypted["tag"]
)
assert decrypted == plaintext  # ✓
```

### FALCON-512 (crypto_utils.py)

- **Algorithm**: FALCON (post-quantum signature scheme, NIST finalist)
- **Key size**: ~900 bytes private, ~900 bytes public
- **Fallback**: RSA-2048 PSS if liboqs unavailable
- **JWT**: Token header contains `"alg": "FALCON-512"`

**Example:**
```python
from crypto_utils import generate_falcon_keypair, falcon_sign, falcon_verify

pub, priv = generate_falcon_keypair()  # FALCON or RSA fallback
message = b"Invoice #001"

signature = falcon_sign(priv, message)
is_valid = falcon_verify(pub, message, signature)  # True
```

### Argon2 Password Hashing (auth.py)

- **Algorithm**: Argon2id (memory-hard, resistant to GPU attacks)
- **Output**: Hashed string with salt embedded
- **Library**: argon2-cffi

**Example:**
```python
from auth import hash_password, verify_password

hashed = hash_password("user_password")
is_correct = verify_password("user_password", hashed)  # True
is_wrong = verify_password("wrong", hashed)             # False
```

---

## Testing Checklist ✅

- [x] crypto_utils.py self-test passes
- [x] main.py starts without errors
- [x] demo.py completes successfully
- [x] Register creates new user
- [x] Login returns valid JWT
- [x] JWT decodes correctly
- [x] FALCON signature present in JWT
- [x] demo.py server subprocess cleanup works

---

## Demo Run

Run `python demo.py` in terminal to exercise the full API flow.

The demo shows:
- registration
- login
- JWT creation
- JWT decoding and structure verification
- cleanup of the server subprocess

**Key points:**
- AES-256-GCM for authenticated symmetric encryption
- FALCON-512 (or RSA fallback) for JWT signatures
- Argon2 for password hashing
- JWT for stateless authentication
- All operations logged with rich colors for clarity

---

## Phase 1 Roadmap (Next Week)

After Phase 0, the following features are planned:

- [ ] PostgreSQL integration with SQLAlchemy
- [ ] AES-encrypted columns for PII (email, address)
- [ ] ECDHE key exchange simulation
- [ ] JWT middleware for protected endpoints
- [ ] Audit log with FALCON signatures
- [ ] Penetration testing suite
- [ ] Performance benchmarking

---

## Troubleshooting

### liboqs not found
- FALCON falls back to RSA-2048 automatically
- Signature still valid, just using RSA instead of post-quantum FALCON
- To use real FALCON: `pip install liboqs-python`

### Port 8000 already in use
- Change port in main.py: `port=8001`
- Or kill existing process: `lsof -i :8000` then `kill -9 <PID>`

### Demo.py hangs
- Ensure main.py has no syntax errors: `python main.py` (Ctrl+C after startup)
- Check port 8000 is free
- httpx timeout is 3 seconds per request

---

## Student Notes

- All crypto operations print intermediate values for learning
- Follow ECDHE_lab_menu_v2.py style: print hex values, show steps
- JWT is not encrypted, only signed — ciphertext is base64url visible but signature ensures authenticity
- FALCON-512 provides post-quantum security: resistant to future quantum computers
- This demo proves "real cryptography" not just theory

---

**Last updated**: June 19, 2026 @ 23:45  
**Demo status**: Ready to run ✅
**Prepared by**: Security Systems Project Team
