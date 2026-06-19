"""
JWT creation and verification using FALCON signatures. 
Follows HMAC.py pattern: choose algorithm, generate key, compute MAC.
"""

import json
import time
import base64
import binascii
from datetime import datetime, timedelta
from rich import print

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash

from crypto_utils import falcon_sign, falcon_verify

# Global password hasher instance
_ph = PasswordHasher()


def hash_password(password: str) -> str:
    """
    Hash a password using argon2.
    
    Args:
        password: plaintext password
        
    Returns:
        hashed password string
    """
    print("Hashing password with Argon2...")
    hashed = _ph.hash(password)
    print(f"Hash (first 40 chars): {hashed[:40]}...")
    return hashed


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        password: plaintext password to check
        hashed: previously hashed password
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        _ph.verify(hashed, password)
        print("OK Password verified")
        return True
    except (VerifyMismatchError, InvalidHash):
        print("FAIL Password verification failed")
        return False


def create_jwt(payload: dict, falcon_private_key: bytes) -> str:
    """
    Create a JWT signed with FALCON private key.
    
    Format: header.payload.signature (base64url encoded)
    
    Args:
        payload: dict to encode in JWT
        falcon_private_key: FALCON-512 private key for signing
        
    Returns:
        JWT token string
    """
    print("Creating JWT with FALCON signature...")
    
    # JWT Header
    header = {
        "alg": "FALCON-512",
        "typ": "JWT"
    }
    
    # Add standard JWT claims
    payload_with_claims = {
        **payload,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600  # 1 hour expiry
    }
    
    # Encode header and payload as base64url
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(',', ':')).encode()
    ).decode().rstrip('=')
    
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload_with_claims, separators=(',', ':')).encode()
    ).decode().rstrip('=')
    
    # Create signing input
    signing_input = f"{header_b64}.{payload_b64}".encode()
    
    # Sign with FALCON
    print(f"Payload: {json.dumps(payload_with_claims)}")
    signature = falcon_sign(falcon_private_key, signing_input)
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
    
    jwt_token = f"{signing_input.decode()}.{signature_b64}"
    print(f"OK JWT created")
    print(f"Token (first 50 chars): {jwt_token[:50]}...\n")
    
    return jwt_token


def verify_jwt(token: str, falcon_public_key: bytes) -> dict:
    """
    Verify and decode a JWT using FALCON public key.
    
    Args:
        token: JWT token string
        falcon_public_key: FALCON-512 public key for verification
        
    Returns:
        decoded payload dict
        
    Raises:
        ValueError: if token is invalid or expired
    """
    print("Verifying JWT with FALCON signature...")
    
    try:
        # Split token into 3 parts
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Decode with padding
        def add_padding(b64_str):
            padding = 4 - (len(b64_str) % 4)
            if padding != 4:
                b64_str += '=' * padding
            return b64_str
        
        header = json.loads(
            base64.urlsafe_b64decode(add_padding(header_b64))
        )
        payload = json.loads(
            base64.urlsafe_b64decode(add_padding(payload_b64))
        )
        signature = base64.urlsafe_b64decode(add_padding(signature_b64))
        
        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}".encode()
        is_valid = falcon_verify(falcon_public_key, signing_input, signature)
        
        if not is_valid:
            raise ValueError("FALCON signature verification failed")
        
        # Check expiry
        exp = payload.get("exp")
        if exp and exp < time.time():
            raise ValueError("JWT token expired")
        
        print(f"Payload: {json.dumps(payload)}")
        print(f"OK JWT verified and valid\n")
        
        return payload
        
    except Exception as e:
        print(f"FAIL JWT verification failed: {str(e)}\n")
        raise ValueError(f"JWT verification failed: {str(e)}")
