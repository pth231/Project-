"""
Order service for secure order processing.

Features:
- ECDHE key exchange with mock payment gateway
- Invoice creation and FALCON signing
- AES-256-GCM encryption
- Non-repudiation guarantee

Process:
1. ECDHE: Generate ephemeral keypair, derive shared session key
2. Create invoice dict
3. FALCON sign invoice hash
4. AES encrypt invoice
5. Store in order
6. Audit log
"""

import json
import hashlib
import base64
import uuid
from datetime import datetime, timezone
from pydantic import BaseModel
from rich import print

from crypto_utils import (
    ecdhe_generate_keypair,
    ecdhe_derive_session_key,
    aes_encrypt,
    falcon_sign,
    falcon_verify
)
from audit import log_event


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class OrderRequest(BaseModel):
    """Request model for creating an order."""
    product_name: str
    quantity: int
    unit_price: float


class OrderResponse(BaseModel):
    """Response model for order creation."""
    order_id: str
    total: float
    invoice_signature: str
    session_key_fingerprint: str
    message: str


# ============================================================================
# ORDER SERVICE
# ============================================================================

def create_order_with_signature(
    order_request: OrderRequest,
    username: str,
    falcon_private_key: bytes,
    falcon_public_key: bytes
) -> tuple:  # Changed: return tuple of (OrderResponse, invoice_dict)
    """
    Create a secure order with ECDHE, FALCON signature, and AES encryption.
    
    Step A: ECDHE key exchange with mock payment gateway
    Step B: Create invoice dict
    Step C: FALCON sign invoice
    Step D: AES encrypt invoice
    Step E: Audit log
    Step F: Return response
    
    Args:
        order_request: OrderRequest with product_name, quantity, unit_price
        username: user who placed the order
        falcon_private_key: FALCON-512 private key for signing
        falcon_public_key: FALCON-512 public key for verification
        
    Returns:
        tuple of (OrderResponse, invoice_dict) for storage and verification
    """
    print(f"\n[cyan bold]=== SECURE ORDER PROCESSING ===[/cyan bold]")
    
    # ========== STEP A: ECDHE Key Exchange ==========
    print(f"\n[yellow]Step A: ECDHE Key Exchange[/yellow]")
    print(f"[dim]Establishing session key with mock payment gateway...[/dim]")
    
    try:
        # Server ephemeral keypair
        server_kp = ecdhe_generate_keypair(group_name="x25519")
        print(f"[dim]✓ Server ephemeral keypair generated[/dim]")
        
        # Mock gateway keypair
        gw_kp = ecdhe_generate_keypair(group_name="x25519")
        print(f"[dim]✓ Mock gateway keypair generated[/dim]")
        
        # Derive shared session key
        session_key = ecdhe_derive_session_key(
            server_kp["private_key"],
            gw_kp["public_key_raw"],
            group_name="x25519"
        )
        print(f"[green]✓ ECDHE session key established with payment gateway[/green]")
        
    except Exception as e:
        print(f"[red]✗ ECDHE failed: {str(e)}[/red]")
        raise
    
    # ========== STEP B: Create Invoice ==========
    print(f"\n[yellow]Step B: Create Invoice[/yellow]")
    
    order_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    total = order_request.quantity * order_request.unit_price
    
    invoice = {
        "order_id": order_id,
        "username": username,
        "product": order_request.product_name,
        "quantity": order_request.quantity,
        "unit_price": order_request.unit_price,
        "total": total,
        "timestamp": timestamp,
        "currency": "VND"
    }
    
    print(f"[dim]Order ID: {order_id}[/dim]")
    print(f"[dim]Product: {order_request.product_name}[/dim]")
    print(f"[dim]Quantity: {order_request.quantity}[/dim]")
    print(f"[dim]Unit price: {order_request.unit_price}[/dim]")
    print(f"[dim]Total: {total}[/dim]")
    
    # ========== STEP C: FALCON Sign Invoice ==========
    print(f"\n[yellow]Step C: FALCON Sign Invoice (Non-repudiation)[/yellow]")
    
    invoice_bytes = json.dumps(invoice, sort_keys=True).encode()
    invoice_hash = hashlib.sha256(invoice_bytes).digest()
    
    print(f"[dim]Invoice JSON length: {len(invoice_bytes)} bytes[/dim]")
    print(f"[dim]SHA-256 hash: {invoice_hash.hex()[:32]}...[/dim]")
    
    signature = falcon_sign(falcon_private_key, invoice_hash)
    signature_b64 = base64.b64encode(signature).decode()
    
    print(f"[dim]Signature (first 50 chars): {signature_b64[:50]}...[/dim]")
    print(f"[green]✓ Invoice signed with FALCON-512[/green]")
    print(f"[green]✓ Non-repudiation guarantee: {username} cannot deny this order[/green]")
    
    # ========== STEP D: AES Encrypt Invoice ==========
    print(f"\n[yellow]Step D: AES-256-GCM Encrypt Invoice[/yellow]")
    
    encrypted_invoice = aes_encrypt(invoice_bytes, session_key)
    
    print(f"[dim]Ciphertext length: {len(encrypted_invoice['ciphertext'])} hex chars[/dim]")
    print(f"[dim]Nonce: {encrypted_invoice['nonce'][:32]}...[/dim]")
    print(f"[dim]Auth tag: {encrypted_invoice['tag']}[/dim]")
    print(f"[green]✓ Invoice encrypted with session key from ECDHE[/green]")
    
    # ========== STEP E: Audit Log ==========
    print(f"\n[yellow]Step E: Audit Log[/yellow]")
    
    log_event(
        action="ORDER_PLACED",
        user_id=username,
        detail=f"order_id={order_id} total={total} product={order_request.product_name}",
        falcon_private_key=falcon_private_key,
        falcon_public_key=falcon_public_key
    )
    
    # ========== STEP F: Return Response ==========
    print(f"\n[yellow]Step F: Return Response[/yellow]")
    
    # Compute session key fingerprint (proof of ECDHE)
    session_key_fp = hashlib.sha256(session_key).hexdigest()[:16]
    
    response = OrderResponse(
        order_id=order_id,
        total=total,
        invoice_signature=signature_b64,
        session_key_fingerprint=session_key_fp,
        message="Order placed — FALCON signature guarantees non-repudiation"
    )
    
    print(f"[dim]Session key fingerprint: {session_key_fp}[/dim]")
    print(f"[green]✓ Order created successfully[/green]")
    
    return (response, invoice)


def verify_order_signature(
    order_id: str,
    invoice_data: dict,
    signature_b64: str,
    falcon_public_key: bytes
) -> bool:
    """
    Verify FALCON signature of an order invoice.
    
    Args:
        order_id: order ID for logging
        invoice_data: invoice dict
        signature_b64: base64-encoded FALCON signature
        falcon_public_key: FALCON-512 public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    print(f"\n[cyan]=== VERIFY ORDER SIGNATURE ===[/cyan]")
    print(f"[dim]Order ID: {order_id}[/dim]")
    
    try:
        # Recompute invoice hash
        invoice_bytes = json.dumps(invoice_data, sort_keys=True).encode()
        invoice_hash = hashlib.sha256(invoice_bytes).digest()
        
        # Decode signature
        signature = base64.b64decode(signature_b64)
        
        # Verify
        print(f"[dim]Invoice JSON length: {len(invoice_bytes)} bytes[/dim]")
        print(f"[dim]SHA-256 hash: {invoice_hash.hex()[:32]}...[/dim]")
        
        is_valid = falcon_verify(falcon_public_key, invoice_hash, signature)
        
        if is_valid:
            print(f"[green]✓ Order signature valid[/green]")
            print(f"[green]✓ Order is non-repudiable: user cannot deny placing this order[/green]")
            return True
        else:
            print(f"[red]✗ Order signature verification failed[/red]")
            print(f"[red]✗ Order may have been tampered with[/red]")
            return False
            
    except Exception as e:
        print(f"[red]✗ Signature verification error: {str(e)}[/red]")
        return False


# Demo function
if __name__ == "__main__":
    from crypto_utils import generate_falcon_keypair
    
    print("[cyan bold]=== ORDER SERVICE DEMO ===[/cyan bold]")
    
    # Generate keypair
    pub_key, priv_key = generate_falcon_keypair()
    
    # Create order request
    order_req = OrderRequest(
        product_name="Laptop Dell XPS 13",
        quantity=1,
        unit_price=1200.00
    )
    
    # Process order
    response, invoice_data = create_order_with_signature(
        order_request=order_req,
        username="alice",
        falcon_private_key=priv_key,
        falcon_public_key=pub_key
    )
    
    print(f"\n[cyan]=== ORDER RESPONSE ===[/cyan]")
    print(f"[dim]Order ID: {response.order_id}[/dim]")
    print(f"[dim]Total: {response.total}[/dim]")
    print(f"[dim]Session key FP: {response.session_key_fingerprint}[/dim]")
    print(f"[dim]Message: {response.message}[/dim]")
    
    # Verify signature (using the EXACT invoice data that was signed)
    verify_order_signature(
        response.order_id,
        invoice_data,
        response.invoice_signature,
        pub_key
    )
    
    print("\n[green]Demo complete[/green]")
