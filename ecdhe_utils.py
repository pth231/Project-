"""
ecdhe_utils.py 	6 ECDHE Key Exchange for Secure Shopping Platform
Topic 6: Application Scenarios 	6 Online Shopping Service Platform

Wraps ECDHE_lab_menu_v2.py (provided by instructor) with project-specific
functions for secure session key establishment between client and server.

Algorithms supported: x25519, secp256r1, x448
KDF: HKDF-SHA256 (derived from shared secret)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ECDHE_lab_menu_v2 import (
    generate_private_key,
    public_key_to_raw,
    ecdh_exchange,
    hkdf_derive,
    load_raw_public_key,
    GROUP_LOOKUP,
)

from rich import print
import binascii

SUPPORTED_GROUPS = ["x25519", "x448", "secp256r1", "secp384r1"]


def ecdhe_generate_keypair(group_name: str = "x25519") -> dict:
    """
    Generate an ephemeral ECDHE keypair for one session.
    A new keypair must be generated for every session (forward secrecy).

    Args:
        group_name: ECDHE group, default x25519 (used in TLS 1.3)

    Returns:
        dict with keys: private_key (object), public_key_raw (bytes), group (str)
    """
    if group_name not in SUPPORTED_GROUPS:
        raise ValueError(f"Unsupported group. Choose from: {SUPPORTED_GROUPS}")

    group = GROUP_LOOKUP[group_name]
    private_key = generate_private_key(group)
    public_key_raw = public_key_to_raw(private_key.public_key(), group)

    print(f"=== ECDHE Keypair ({group_name}) ===")
    print(f"Public key ({len(public_key_raw)} bytes): {public_key_raw.hex()[:32]}...")
    print(f"Note: private key stays in memory, never transmitted")

    return {
        "private_key": private_key,
        "public_key_raw": public_key_raw,
        "group": group_name,
    }


def ecdhe_derive_session_key(
    private_key,
    peer_public_raw: bytes,
    group_name: str = "x25519",
    info: str = "secure-shop-session",
) -> bytes:
    """
    Derive a 32-byte AES session key from ECDHE shared secret via HKDF.

    Args:
        private_key: our ephemeral private key object
        peer_public_raw: peer's raw public key bytes
        group_name: must match the group used in keypair generation
        info: HKDF context string (binds key to this application)

    Returns:
        32-byte session key for AES-256
    """
    if group_name not in SUPPORTED_GROUPS:
        raise ValueError(f"Unsupported group. Choose from: {SUPPORTED_GROUPS}")

    group = GROUP_LOOKUP[group_name]
    peer_pub = load_raw_public_key(peer_public_raw, group)
    shared_secret = ecdh_exchange(private_key, peer_pub, group)
    session_key = hkdf_derive(
        shared_secret, group,
        key_len=32, hash_name="auto",
        salt=None, info=info.encode()
    )

    print(f"=== ECDHE Session Key Derivation ===")
    print(f"Shared secret ({len(shared_secret)} bytes): {shared_secret.hex()[:32]}...")
    print(f"HKDF info: '{info}'")
    print(f"Session key (32 bytes): {session_key.hex()}")
    print(f"OK Session key derived")

    return session_key


def ecdhe_demo(group_name: str = "x25519") -> bool:
    """
    Simulate full Alice-Bob ECDHE handshake.
    Demonstrates forward secrecy: each run produces different keys.

    Args:
        group_name: ECDHE group to demo

    Returns:
        True if both parties derive the same session key
    """
    print("=" * 60)
    print(f"ECDHE Demo: {group_name} (Forward Secrecy)")
    print("=" * 60)

    print("\nStep 1: Each party generates ephemeral keypair")
    alice = ecdhe_generate_keypair(group_name)
    bob = ecdhe_generate_keypair(group_name)

    print("\nStep 2: Exchange public keys (sent over network)")
    print(f"Alice sends public key to Bob: {alice['public_key_raw'].hex()[:32]}...")
    print(f"Bob sends public key to Alice: {bob['public_key_raw'].hex()[:32]}...")

    print("\nStep 3: Each derives session key independently")
    alice_key = ecdhe_derive_session_key(
        alice["private_key"], bob["public_key_raw"], group_name
    )
    bob_key = ecdhe_derive_session_key(
        bob["private_key"], alice["public_key_raw"], group_name
    )

    print("\nStep 4: Verify both keys match")
    match = alice_key == bob_key
    print(f"Alice session key: {alice_key.hex()}")
    print(f"Bob session key:   {bob_key.hex()}")
    print(f"Keys match: {match}")
    print("OK Forward secrecy demonstrated — run again to see different keys" if match else "FAIL Keys do not match")

    return match


if __name__ == "__main__":
    print("=" * 60)
    print("ecdhe_utils.py Self-Test")
    print("=" * 60)

    for group in ["x25519", "secp256r1"]:
        print(f"\nTesting group: {group}")
        result = ecdhe_demo(group)
        assert result, f"ECDHE demo failed for {group}"
        print(f"OK {group} passed\n")

    print("=" * 60)
    print("All ecdhe_utils tests passed!")
    print("=" * 60)
