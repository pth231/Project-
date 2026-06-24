"""
Audit logging module for FastAPI project.
Provides non-repudiation guarantee using FALCON signatures.
- log_event: Create signed audit log entry
- verify_log_integrity: Verify all audit log entries are authentic
"""

import json
import hashlib
import base64
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from rich import print

from crypto_utils import falcon_sign, falcon_verify, generate_falcon_keypair


def load_or_generate_keypair() -> tuple[bytes, bytes]:
    """
    Load persistent keypair from files, or generate and save if not exist.
    
    Returns:
        Tuple of (public_key: bytes, private_key: bytes)
    """
    if KEYPAIR_FILE_PRIV.exists() and KEYPAIR_FILE_PUB.exists():
        # Load from files
        with open(KEYPAIR_FILE_PRIV, "rb") as f:
            priv_key = f.read()
        with open(KEYPAIR_FILE_PUB, "rb") as f:
            pub_key = f.read()
        print(f"[green]✓ Loaded persistent keypair from files[/green]")
        return pub_key, priv_key
    else:
        # Generate and save
        pub_key, priv_key = generate_falcon_keypair()
        with open(KEYPAIR_FILE_PRIV, "wb") as f:
            f.write(priv_key)
        with open(KEYPAIR_FILE_PUB, "wb") as f:
            f.write(pub_key)
        print(f"[green]✓ Generated and saved persistent keypair[/green]")
        return pub_key, priv_key

# Constants
AUDIT_LOG_PATH = Path("audit_log.jsonl")
KEYPAIR_FILE_PRIV = Path("falcon_private_key.pem")
KEYPAIR_FILE_PUB = Path("falcon_public_key.pem")


def log_event(
    action: str,
    user_id: str,
    detail: str,
    falcon_private_key: bytes,
    falcon_public_key: bytes
) -> dict:
    """
    Log a security event with FALCON signature for non-repudiation.
    
    Args:
        action: Event action (e.g., "LOGIN", "DELETE_USER", "EXPORT_DATA")
        user_id: User identifier
        detail: Event details as string
        falcon_private_key: FALCON-512 private key for signing
        falcon_public_key: FALCON-512 public key (for verification in entry)
        
    Returns:
        The complete audit entry dict (including signature)
    """
    print(f"\n[cyan]=== AUDIT LOG EVENT ===[/cyan]")
    
    # Create entry without signature
    entry_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    
    entry = {
        "timestamp": timestamp,
        "action": action,
        "user_id": user_id,
        "detail": detail,
        "entry_id": entry_id
    }
    
    print(f"[dim]Entry ID: {entry_id}[/dim]")
    print(f"[dim]Timestamp: {timestamp}[/dim]")
    print(f"[dim]Action: {action}[/dim]")
    print(f"[dim]User: {user_id}[/dim]")
    print(f"[dim]Detail: {detail}[/dim]")
    
    # Step 1: Compute SHA-256 hash of entry
    entry_json = json.dumps(entry, sort_keys=True)
    entry_bytes = entry_json.encode()
    hash_value = hashlib.sha256(entry_bytes).digest()
    
    print(f"\n[yellow]Step 1: Compute SHA-256[/yellow]")
    print(f"[dim]Entry JSON: {entry_json}[/dim]")
    print(f"[dim]SHA-256: {hash_value.hex()[:32]}...[/dim]")
    
    # Step 2: Sign hash with FALCON
    print(f"\n[yellow]Step 2: Sign with FALCON-512[/yellow]")
    signature = falcon_sign(falcon_private_key, hash_value)
    signature_b64 = base64.b64encode(signature).decode()
    
    print(f"[dim]Signature (base64, first 50 chars): {signature_b64[:50]}...[/dim]")
    
    # Step 3: Create final entry with signature
    final_entry = {**entry, "signature": signature_b64}
    
    # Step 4: Append to audit_log.jsonl
    print(f"\n[yellow]Step 3: Append to audit_log.jsonl[/yellow]")
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(final_entry) + "\n")
    
    print(f"[dim]File: {AUDIT_LOG_PATH}[/dim]")
    print(f"[green]✓ Entry appended to audit log[/green]")
    
    # Step 5: Print summary
    print(f"\n[green]AUDIT [{action}] user={user_id} id={entry_id}[/green]")
    
    return final_entry


def verify_log_integrity(falcon_public_key: bytes) -> bool:
    """
    Verify integrity and authenticity of all audit log entries.
    
    Each entry is verified by:
    1. Extracting signature
    2. Recomputing SHA-256 of remaining fields (without signature)
    3. Verifying signature with FALCON public key
    
    Args:
        falcon_public_key: FALCON-512 public key for verification
        
    Returns:
        True if all entries are valid, False if any entry fails verification
    """
    print(f"\n[cyan]=== VERIFY AUDIT LOG INTEGRITY ===[/cyan]")
    
    if not AUDIT_LOG_PATH.exists():
        print(f"[yellow]⚠ Audit log not found: {AUDIT_LOG_PATH}[/yellow]")
        return True  # No log to verify
    
    verified_count = 0
    failed_entries = []
    
    with open(AUDIT_LOG_PATH, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                entry_with_sig = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"[red]✗ Line {line_num}: Invalid JSON - {str(e)}[/red]")
                failed_entries.append(line_num)
                continue
            
            print(f"\n[dim]Line {line_num}: Entry ID = {entry_with_sig.get('entry_id', 'N/A')}[/dim]")
            
            # Extract signature
            signature_b64 = entry_with_sig.get("signature")
            if not signature_b64:
                print(f"[red]✗ Line {line_num}: Missing signature field[/red]")
                failed_entries.append(line_num)
                continue
            
            # Decode signature
            try:
                signature = base64.b64decode(signature_b64)
            except Exception as e:
                print(f"[red]✗ Line {line_num}: Invalid base64 signature - {str(e)}[/red]")
                failed_entries.append(line_num)
                continue
            
            # Remove signature from entry to recompute hash
            entry_without_sig = {k: v for k, v in entry_with_sig.items() if k != "signature"}
            entry_json = json.dumps(entry_without_sig, sort_keys=True)
            hash_value = hashlib.sha256(entry_json.encode()).digest()
            
            print(f"[dim]  SHA-256: {hash_value.hex()[:32]}...[/dim]")
            
            # Verify signature
            is_valid = falcon_verify(falcon_public_key, hash_value, signature)
            
            if is_valid:
                print(f"[green]✓ Signature valid[/green]")
                verified_count += 1
            else:
                print(f"[red]✗ Signature verification failed[/red]")
                print(f"[red]  Entry: {line}[/red]")
                failed_entries.append(line_num)
    
    # Summary
    print(f"\n[cyan]--- Verification Summary ---[/cyan]")
    
    if failed_entries:
        print(f"[red]✗ Failed entries (lines): {failed_entries}[/red]")
        print(f"[red]Audit log integrity: FAILED[/red]")
        return False
    else:
        print(f"[green]✓ Audit log integrity: OK — {verified_count} entries verified[/green]")
        return True


# Demo function
if __name__ == "__main__":
    print("[cyan bold]=== AUDIT LOG DEMO ===[/cyan bold]")
    
    # Load or generate persistent keypair
    pub_key, priv_key = load_or_generate_keypair()
    
    # Log some events
    log_event("LOGIN", "alice", "Logged in from 192.168.1.1", priv_key, pub_key)
    log_event("CREATE_USER", "admin", "Created user bob", priv_key, pub_key)
    log_event("DELETE_DATA", "alice", "Deleted file document.pdf", priv_key, pub_key)
    
    # Verify integrity
    verify_log_integrity(pub_key)
    
    print("\n[green]Demo complete[/green]")
