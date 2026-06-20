"""
This module wraps AES-256-GCM (from PyCryptodome) and FALCON-512 via liboqs.
Style follows ECDHE_lab_menu_v2.py: functions are standalone and print 
intermediate values for learning/demo purposes.
"""

import secrets
import binascii
from typing import Tuple
from rich import print

from Crypto.Cipher import AES
import sys as _sys
_sys.path.insert(0, r"D:\Mat_ma_ung_dung\week5")
try:
    from ECDHE_lab_menu_v2 import (
        generate_private_key as _ecdhe_gen,
        public_key_to_raw as _ecdhe_pub_raw,
        ecdh_exchange as _ecdh_exchange,
        hkdf_derive as _hkdf_derive,
        load_raw_public_key as _load_raw_pub,
        GROUP_LOOKUP as _GROUP_LOOKUP,
    )
    _ECDHE_AVAILABLE = True
except Exception:
    _ECDHE_AVAILABLE = False
    print("! ECDHE_lab_menu_v2 not found — ECDHE functions disabled")

import hashlib
SUPPORTED_HASH_ALGOS = ["sha256","sha384","sha512","sha3_224","sha3_256","sha3_384","sha3_512"]

def hash_message(message: bytes, algo: str = "sha256") -> bytes:
    if algo not in SUPPORTED_HASH_ALGOS:
        raise ValueError(f"Unsupported hash. Choose: {SUPPORTED_HASH_ALGOS}")
    digest = hashlib.new(algo, message).digest()
    print(f"Hash {algo}: {digest.hex()[:32]}...")
    return digest


def aes_encrypt(plaintext: bytes, key: bytes) -> dict:
    """
    Encrypt plaintext using AES-256-GCM.
    
    Args:
        plaintext: bytes to encrypt
        key: 32-byte AES key
        
    Returns:
        dict with keys: ciphertext, nonce, tag (all hex strings)
    """
    print("=== AES-256-GCM Encrypt ===")
    
    # Generate random 16-byte nonce
    nonce = secrets.token_bytes(16)
    print(f"Nonce (16 bytes): {binascii.hexlify(nonce).decode()}")
    
    # Create cipher and encrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    print(f"Key size: {len(key)} bytes")
    print(f"Plaintext size: {len(plaintext)} bytes")
    print(f"Ciphertext size: {len(ciphertext)} bytes")
    print(f"Auth tag (16 bytes): {binascii.hexlify(tag).decode()}")
    
    ciphertext_hex = binascii.hexlify(ciphertext).decode()
    nonce_hex = binascii.hexlify(nonce).decode()
    tag_hex = binascii.hexlify(tag).decode()
    
    print(f"OK Encryption successful")
    
    return {
        "ciphertext": ciphertext_hex,
        "nonce": nonce_hex,
        "tag": tag_hex
    }


def aes_decrypt(ciphertext_hex: str, key: bytes, nonce_hex: str, tag_hex: str) -> bytes:
    """
    Decrypt ciphertext using AES-256-GCM.
    
    Args:
        ciphertext_hex: encrypted data as hex string
        key: 32-byte AES key
        nonce_hex: nonce as hex string
        tag_hex: authentication tag as hex string
        
    Returns:
        plaintext bytes
        
    Raises:
        ValueError: if tag verification fails
    """
    print("=== AES-256-GCM Decrypt ===")
    
    # Convert hex to bytes
    ciphertext = binascii.unhexlify(ciphertext_hex)
    nonce = binascii.unhexlify(nonce_hex)
    tag = binascii.unhexlify(tag_hex)
    
    print(f"Ciphertext size: {len(ciphertext)} bytes")
    print(f"Nonce (16 bytes): {nonce_hex}")
    print(f"Auth tag (16 bytes): {tag_hex}")
    
    # Create cipher and decrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"Plaintext size: {len(plaintext)} bytes")
        print(f"OK Decryption and verification successful")
        return plaintext
    except ValueError as e:
        print(f"FAIL Tag verification failed: {str(e)}")
        raise ValueError(f"Tag verification failed: {str(e)}")


def generate_falcon_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a FALCON-512 keypair.
    Falls back to RSA-2048 if liboqs is not available.
    
    Returns:
        tuple of (public_key_bytes, private_key_bytes)
    """
    print("=== Generate Keypair ===")
    
    try:
        import oqs
        print("Attempting to use FALCON-512 (oqs)...")
        sig = oqs.Signature("Falcon-512")
        public_key = sig.generate_keyset()
        private_key = sig.export_secret_key()
        print(f"OK FALCON-512 Public key: {len(public_key)} bytes, Private key: {len(private_key)} bytes")
        return (public_key, private_key)
    except ImportError:
        print("! liboqs not found, using RSA-2048 fallback")
        
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        # Generate RSA-2048 keypair
        private_key_obj = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Serialize keys to PEM
        private_key_pem = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key_obj = private_key_obj.public_key()
        public_key_pem = public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        print(f"RSA-2048 Public key: {len(public_key_pem)} bytes, Private key: {len(private_key_pem)} bytes")
        return (public_key_pem, private_key_pem)


def falcon_sign(private_key: bytes, message: bytes, hash_algo: str = "sha256") -> bytes:
    """
    Sign a message using FALCON-512 private key.
    Falls back to RSA PSS signing if liboqs is not available.
    
    Args:
        private_key: FALCON-512 or RSA private key
        message: message to sign
        
    Returns:
        signature bytes
    """
    print("=== Sign Message ===")
    message = hash_message(message, hash_algo)
    print(f"Message length: {len(message)} bytes")
    
    try:
        import oqs
        print("Algorithm: FALCON-512")
        sig = oqs.Signature("Falcon-512")
        sig.import_secret_key(private_key)
        signature = sig.sign(message)
        print(f"Signature length: {len(signature)} bytes")
        sig_hex_preview = binascii.hexlify(signature[:32]).decode() + "..."
        print(f"Signature (first 32 bytes): {sig_hex_preview}")
        print(f"OK Signature created")
        return signature
    except ImportError:
        print("Algorithm: RSA-2048 PSS")
        
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend
        
        # Load private key from PEM
        private_key_obj = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )
        
        # Sign with RSA PSS
        signature = private_key_obj.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        print(f"Signature length: {len(signature)} bytes")
        sig_hex_preview = binascii.hexlify(signature[:32]).decode() + "..."
        print(f"Signature (first 32 bytes): {sig_hex_preview}")
        print(f"OK Signature created")
        return signature


def falcon_verify(public_key: bytes, message: bytes, signature: bytes, hash_algo: str = "sha256") -> bool:
    """
    Verify a FALCON-512 signature.
    Falls back to RSA verification if liboqs is not available.
    
    Args:
        public_key: FALCON-512 or RSA public key
        message: original message
        signature: signature to verify
        
    Returns:
        True if valid, False otherwise
    """
    print("=== Verify Signature ===")
    message = hash_message(message, hash_algo)
    print(f"Message length: {len(message)} bytes")
    print(f"Signature length: {len(signature)} bytes")
    
    try:
        import oqs
        print("Algorithm: FALCON-512")
        sig = oqs.Signature("Falcon-512")
        sig.import_public_key(public_key)
        is_valid = sig.verify(message, signature)
        
        if is_valid:
            print("OK Signature valid")
            return True
        else:
            print("FAIL Signature invalid")
            return False
    except ImportError:
        print("Algorithm: RSA-2048 PSS")
        
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend
        
        try:
            # Load public key from PEM
            public_key_obj = serialization.load_pem_public_key(
                public_key,
                backend=default_backend()
            )
            
            # Verify signature
            public_key_obj.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            print("OK Signature valid")
            return True
        except Exception:
            print("FAIL Signature invalid")
            return False


def ecdhe_generate_keypair(group_name="x25519") -> dict:
    if not _ECDHE_AVAILABLE:
        raise RuntimeError("ECDHE not available: ECDHE_lab_menu_v2.py not found")
    group = _GROUP_LOOKUP[group_name]
    priv = _ecdhe_gen(group)
    pub_raw = _ecdhe_pub_raw(priv.public_key(), group)
    print(f"=== ECDHE Keypair ({group_name}) ===")
    print(f"Public key ({len(pub_raw)} bytes): {pub_raw.hex()[:32]}...")
    return {"private_key": priv, "public_key_raw": pub_raw, "group": group_name}

def ecdhe_derive_session_key(private_key, peer_public_raw: bytes, group_name="x25519", info="secure-shop") -> bytes:
    if not _ECDHE_AVAILABLE:
        raise RuntimeError("ECDHE not available: ECDHE_lab_menu_v2.py not found")
    group = _GROUP_LOOKUP[group_name]
    peer_pub = _load_raw_pub(peer_public_raw, group)
    shared = _ecdh_exchange(private_key, peer_pub, group)
    key = _hkdf_derive(shared, group, key_len=32, hash_name="auto", salt=None, info=info.encode())
    print(f"=== ECDHE Session Key ===")
    print(f"Shared secret: {shared.hex()[:32]}...")
    print(f"Session key:   {key.hex()}")
    return key

def ecdhe_demo(group_name="x25519") -> bool:
    if not _ECDHE_AVAILABLE:
        raise RuntimeError("ECDHE not available: ECDHE_lab_menu_v2.py not found")
    print("=" * 60)
    print(f"ECDHE Demo: {group_name}")
    print("=" * 60)
    nguyen_van_A = ecdhe_generate_keypair(group_name)
    nguyen_van_B   = ecdhe_generate_keypair(group_name)
    ak = ecdhe_derive_session_key(nguyen_van_A["private_key"], nguyen_van_B["public_key_raw"],   group_name)
    bk = ecdhe_derive_session_key(nguyen_van_B["private_key"],   nguyen_van_A["public_key_raw"], group_name)
    ok = ak == bk
    print(f"nguyen van A key == nguyen van B key: {ok}")
    print("OK Forward secrecy demonstrated" if ok else "FAIL Keys do not match")
    return ok


if __name__ == "__main__":
    print("" + "=" * 76)
    print("crypto_utils.py Self-Test")
    print("=" * 76 + "\n")
    
    # Test 1: AES encryption/decryption
    print("Test 1: AES-256-GCM\n")
    aes_key = secrets.token_bytes(32)
    plaintext = b"Hello Secure Shop!"
    
    encrypted = aes_encrypt(plaintext, aes_key)
    print()
    
    decrypted = aes_decrypt(
        encrypted["ciphertext"],
        aes_key,
        encrypted["nonce"],
        encrypted["tag"]
    )
    print()
    
    assert decrypted == plaintext, "AES decrypt failed!"
    print("OK AES encryption/decryption test passed\n")
    
    # Test 2: FALCON keypair and signing
    print("Test 2: FALCON Signing\n")
    pub_key, priv_key = generate_falcon_keypair()
    print()
    
    message = b"Test invoice #001"
    signature = falcon_sign(priv_key, message)
    print()
    
    is_valid = falcon_verify(pub_key, message, signature)
    print()
    
    assert is_valid, "FALCON verification failed!"
    print("OK FALCON signing/verification test passed\n")

    # Test 3: ECDHE key exchange
    print("Test 3: ECDHE Key Exchange\n")
    assert ecdhe_demo(), "ECDHE failed!"
    print("OK ECDHE test passed\n")
    
    # Final summary
    print("" + "=" * 76)
    print("=== All crypto_utils self-tests passed! ===")
    print("=" * 76 + "")
