"""
This module wraps AES-256-GCM (from PyCryptodome) and FALCON-512 via liboqs.
Style follows teacher's ECDHE_lab_menu_v2.py: functions are standalone, print 
intermediate values for teaching/demo purposes.
"""

import secrets
import binascii
from typing import Tuple
from rich import print

from Crypto.Cipher import AES


def aes_encrypt(plaintext: bytes, key: bytes) -> dict:
    """
    Encrypt plaintext using AES-256-GCM.
    
    Args:
        plaintext: bytes to encrypt
        key: 32-byte AES key
        
    Returns:
        dict with keys: ciphertext, nonce, tag (all hex strings)
    """
    print("[bold cyan]=== AES-256-GCM Encrypt ===[/bold cyan]")
    
    # Generate random 16-byte nonce
    nonce = secrets.token_bytes(16)
    print(f"[yellow]Nonce (16 bytes):[/yellow] {binascii.hexlify(nonce).decode()}")
    
    # Create cipher and encrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    print(f"[yellow]Key size:[/yellow] {len(key)} bytes")
    print(f"[yellow]Plaintext size:[/yellow] {len(plaintext)} bytes")
    print(f"[yellow]Ciphertext size:[/yellow] {len(ciphertext)} bytes")
    print(f"[yellow]Auth tag (16 bytes):[/yellow] {binascii.hexlify(tag).decode()}")
    
    ciphertext_hex = binascii.hexlify(ciphertext).decode()
    nonce_hex = binascii.hexlify(nonce).decode()
    tag_hex = binascii.hexlify(tag).decode()
    
    print(f"[green]✓ Encryption successful[/green]")
    
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
    print("[bold cyan]=== AES-256-GCM Decrypt ===[/bold cyan]")
    
    # Convert hex to bytes
    ciphertext = binascii.unhexlify(ciphertext_hex)
    nonce = binascii.unhexlify(nonce_hex)
    tag = binascii.unhexlify(tag_hex)
    
    print(f"[yellow]Ciphertext size:[/yellow] {len(ciphertext)} bytes")
    print(f"[yellow]Nonce (16 bytes):[/yellow] {nonce_hex}")
    print(f"[yellow]Auth tag (16 bytes):[/yellow] {tag_hex}")
    
    # Create cipher and decrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"[yellow]Plaintext size:[/yellow] {len(plaintext)} bytes")
        print(f"[green]✓ Decryption and verification successful[/green]")
        return plaintext
    except ValueError as e:
        print(f"[red]✗ Tag verification failed: {str(e)}[/red]")
        raise ValueError(f"Tag verification failed: {str(e)}")


def generate_falcon_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a FALCON-512 keypair.
    Falls back to RSA-2048 if liboqs is not available.
    
    Returns:
        tuple of (public_key_bytes, private_key_bytes)
    """
    print("[bold cyan]=== Generate Keypair ===[/bold cyan]")
    
    try:
        import liboqs
        print("[yellow]Attempting to use FALCON-512 (liboqs)...[/yellow]")
        sig = liboqs.OQS_SIG("Falcon-512")
        public_key = sig.generate_keyset()
        private_key = sig.export_secret_key()
        print(f"[green]✓ FALCON-512[/green] Public key: {len(public_key)} bytes, Private key: {len(private_key)} bytes")
        return (public_key, private_key)
    except ImportError:
        print("[yellow]⚠ liboqs not found, using RSA-2048 fallback[/yellow]")
        
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
        
        print(f"[yellow]RSA-2048[/yellow] Public key: {len(public_key_pem)} bytes, Private key: {len(private_key_pem)} bytes")
        return (public_key_pem, private_key_pem)


def falcon_sign(private_key: bytes, message: bytes) -> bytes:
    """
    Sign a message using FALCON-512 private key.
    Falls back to RSA PSS signing if liboqs is not available.
    
    Args:
        private_key: FALCON-512 or RSA private key
        message: message to sign
        
    Returns:
        signature bytes
    """
    print("[bold cyan]=== Sign Message ===[/bold cyan]")
    print(f"[yellow]Message length:[/yellow] {len(message)} bytes")
    
    try:
        import liboqs
        print("[yellow]Algorithm:[/yellow] FALCON-512")
        sig = liboqs.OQS_SIG("Falcon-512")
        sig.import_secret_key(private_key)
        signature = sig.sign(message)
        print(f"[yellow]Signature length:[/yellow] {len(signature)} bytes")
        sig_hex_preview = binascii.hexlify(signature[:32]).decode() + "..."
        print(f"[yellow]Signature (first 32 bytes):[/yellow] {sig_hex_preview}")
        print(f"[green]✓ Signature created[/green]")
        return signature
    except ImportError:
        print("[yellow]Algorithm:[/yellow] RSA-2048 PSS")
        
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
        
        print(f"[yellow]Signature length:[/yellow] {len(signature)} bytes")
        sig_hex_preview = binascii.hexlify(signature[:32]).decode() + "..."
        print(f"[yellow]Signature (first 32 bytes):[/yellow] {sig_hex_preview}")
        print(f"[green]✓ Signature created[/green]")
        return signature


def falcon_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
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
    print("[bold cyan]=== Verify Signature ===[/bold cyan]")
    print(f"[yellow]Message length:[/yellow] {len(message)} bytes")
    print(f"[yellow]Signature length:[/yellow] {len(signature)} bytes")
    
    try:
        import liboqs
        print("[yellow]Algorithm:[/yellow] FALCON-512")
        sig = liboqs.OQS_SIG("Falcon-512")
        sig.import_public_key(public_key)
        is_valid = sig.verify(message, signature)
        
        if is_valid:
            print("[green]✓ Signature valid[/green]")
            return True
        else:
            print("[red]✗ Signature invalid[/red]")
            return False
    except ImportError:
        print("[yellow]Algorithm:[/yellow] RSA-2048 PSS")
        
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
            
            print("[green]✓ Signature valid[/green]")
            return True
        except Exception:
            print("[red]✗ Signature invalid[/red]")
            return False


if __name__ == "__main__":
    print("[bold]" + "=" * 76)
    print("crypto_utils.py Self-Test")
    print("=" * 76 + "[/bold]\n")
    
    # Test 1: AES encryption/decryption
    print("[bold cyan]Test 1: AES-256-GCM[/bold cyan]\n")
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
    print("[green]✓ AES encryption/decryption test passed[/green]\n")
    
    # Test 2: FALCON keypair and signing
    print("[bold cyan]Test 2: FALCON Signing[/bold cyan]\n")
    pub_key, priv_key = generate_falcon_keypair()
    print()
    
    message = b"Test invoice #001"
    signature = falcon_sign(priv_key, message)
    print()
    
    is_valid = falcon_verify(pub_key, message, signature)
    print()
    
    assert is_valid, "FALCON verification failed!"
    print("[green]✓ FALCON signing/verification test passed[/green]\n")
    
    # Final summary
    print("[bold cyan]" + "=" * 76)
    print("=== All crypto_utils self-tests passed! ===")
    print("=" * 76 + "[/bold cyan]")
