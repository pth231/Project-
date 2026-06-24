from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel
import uvicorn
from rich import print
from time import time
from collections import defaultdict

from auth import hash_password, verify_password, create_jwt, verify_jwt, get_current_user, require_role
from crypto_utils import generate_falcon_keypair
from order_service import OrderRequest, create_order_with_signature, verify_order_signature

app = FastAPI(title="Secure Shop API", version="0.1.0")

# In-memory storage
users_db = {}  # {username: {"password_hash": str, "email": str, "role": str}}
orders_db = {}  # {order_id: {"order_data": dict, "signature": str, "timestamp": str}}

# Rate limiter for brute force protection
failed_login_attempts = defaultdict(list)  # {username: [(timestamp1, ...), ...]}
RATE_LIMIT_ATTEMPTS = 5  # Max attempts
RATE_LIMIT_WINDOW = 900  # 15 minutes in seconds

def check_rate_limit(username: str) -> bool:
    """Check if username has exceeded login attempt limit. Returns True if allowed, False if blocked."""
    current_time = time()
    
    # Clean old attempts outside the time window
    failed_login_attempts[username] = [
        timestamp for timestamp in failed_login_attempts[username]
        if current_time - timestamp < RATE_LIMIT_WINDOW
    ]
    
    # Check if exceeded limit
    if len(failed_login_attempts[username]) >= RATE_LIMIT_ATTEMPTS:
        return False  # Rate limited
    
    return True  # Allowed

def record_failed_login(username: str):
    """Record a failed login attempt."""
    failed_login_attempts[username].append(time())

def reset_failed_attempts(username: str):
    """Reset failed login attempts after successful login."""
    failed_login_attempts[username] = []

# Generate FALCON keypair for JWT signing on startup
try:
    FALCON_PUBLIC_KEY, FALCON_PRIVATE_KEY = generate_falcon_keypair()
    print("OK FALCON keypair generated for JWT signing")
except Exception as e:
    print(f"FAIL Failed to generate FALCON keypair: {str(e)}")
    raise

# Store public key in app state for dependency injection
app.state.FALCON_PUBLIC_KEY = FALCON_PUBLIC_KEY


# Dependency provider for FALCON_PUBLIC_KEY
def get_falcon_public_key() -> bytes:
    """Dependency to provide FALCON_PUBLIC_KEY to route handlers."""
    return app.state.FALCON_PUBLIC_KEY


# Request models
class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    username: str
    token: str
    message: str


@app.get("/")
def read_root():
    return {"status": "ok", "message": "Secure Shop API running"}


@app.post("/register", response_model=dict)
def register(req: RegisterRequest):
    """
    Register a new user.
    
    - Hash password with Argon2
    - Store in-memory
    - Return success message
    """
    print(f"\n=== POST /register ===")
    print(f"Username: {req.username}")
    print(f"Email: {req.email}")
    
    if req.username in users_db:
        print(f"FAIL User already exists\n")
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Hash password
    hashed = hash_password(req.password)
    
    # Assign role: admin if username is "admin", otherwise customer
    role = "admin" if req.username == "admin" else "customer"
    
    # Store user
    users_db[req.username] = {
        "password_hash": hashed,
        "email": req.email,
        "role": role
    }
    
    print(f"OK User registered with role: {role}\n")
    return {
        "status": "success",
        "username": req.username,
        "message": "Registration successful"
    }


@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest):
    """
    Login user and return FALCON-signed JWT.
    
    - Check rate limiting
    - Verify password
    - Create JWT signed with FALCON
    - Return token
    """
    print(f"\n=== POST /login ===")
    print(f"Username: {req.username}")
    
    # Check rate limit FIRST (before checking if user exists)
    if not check_rate_limit(req.username):
        print(f"FAIL Rate limited (too many failed attempts)\n")
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
    
    if req.username not in users_db:
        print(f"FAIL User not found\n")
        record_failed_login(req.username)  # Record attempt
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    user = users_db[req.username]
    
    # Verify password
    if not verify_password(req.password, user["password_hash"]):
        print(f"FAIL Login failed\n")
        record_failed_login(req.username)  # Record failed attempt
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Successful login - reset failed attempts
    reset_failed_attempts(req.username)
    
    # Create JWT with FALCON signature
    payload = {
        "username": req.username,
        "email": user["email"],
        "role": user.get("role", "customer")
    }
    token = create_jwt(payload, FALCON_PRIVATE_KEY)
    
    print(f"OK Login successful\n")
    return LoginResponse(
        username=req.username,
        token=token,
        message="Login successful - JWT contains FALCON signature"
    )


@app.get("/me")
async def get_user_me(
    request: Request,
    falcon_public_key: bytes = Depends(get_falcon_public_key)
) -> dict:
    """
    Get current authenticated user's information.
    
    Returns user profile from JWT payload.
    Requires valid FALCON-signed JWT in Authorization header.
    """
    current_user = get_current_user(request, falcon_public_key)
    
    print(f"\n=== GET /me ===")
    print(f"[dim]User: {current_user.get('username')}[/dim]")
    
    return {
        "username": current_user.get("username"),
        "email": current_user.get("email"),
        "role": current_user.get("role"),
        "iat": current_user.get("iat"),
        "exp": current_user.get("exp")
    }


@app.get("/admin/users")
async def get_users_list(
    request: Request,
    falcon_public_key: bytes = Depends(get_falcon_public_key)
) -> dict:
    """
    Get list of all users (admin only).
    
    Only users with role='admin' can access this endpoint.
    Password hashes are NOT included in response for security.
    """
    # Check role
    verify_role_fn = require_role("admin")
    current_user = verify_role_fn(request, falcon_public_key)
    
    print(f"\n=== GET /admin/users ===")
    print(f"[dim]Admin: {current_user.get('username')}[/dim]")
    
    # Return user list without password hashes
    user_list = [
        {
            "username": username,
            "email": user_data.get("email"),
            "role": user_data.get("role", "customer")
        }
        for username, user_data in users_db.items()
    ]
    
    print(f"[green]OK Returning {len(user_list)} users[/green]")
    
    return {
        "total": len(user_list),
        "users": user_list
    }


@app.post("/orders")
async def place_order(
    order_request: OrderRequest,
    request: Request,
    falcon_public_key: bytes = Depends(get_falcon_public_key)
) -> dict:
    """
    Place a secure order with ECDHE, FALCON signature, and AES encryption.
    
    Requires:
    - Valid JWT in Authorization header
    - OrderRequest with product_name, quantity, unit_price
    
    Returns:
    - order_id, total, invoice_signature, session_key_fingerprint
    """
    print(f"\n=== POST /orders ===")
    
    # Get current user
    current_user = get_current_user(request, falcon_public_key)
    username = current_user.get("username")
    
    try:
        # Process order with FALCON signature and AES encryption
        response, invoice_data = create_order_with_signature(
            order_request=order_request,
            username=username,
            falcon_private_key=FALCON_PRIVATE_KEY,
            falcon_public_key=falcon_public_key
        )
        
        # Store order in memory
        orders_db[response.order_id] = {
            "username": username,
            "order_data": invoice_data,
            "signature": response.invoice_signature,
            "session_key_fp": response.session_key_fingerprint
        }
        
        print(f"\n[green]✓ Order stored in database[/green]")
        
        return response.dict()
        
    except Exception as e:
        print(f"[red]✗ Order processing failed: {str(e)}[/red]")
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/orders/{order_id}/verify")
async def verify_order(
    order_id: str,
    request: Request,
    falcon_public_key: bytes = Depends(get_falcon_public_key)
) -> dict:
    """
    Verify FALCON signature of an order.
    
    Requires:
    - Valid JWT in Authorization header
    - order_id parameter
    
    Returns:
    - valid: true/false
    - signer: "server"
    - timestamp: verification timestamp
    - message: explanation
    """
    print(f"\n=== GET /orders/{order_id}/verify ===")
    
    # Get current user
    current_user = get_current_user(request, falcon_public_key)
    username = current_user.get("username")
    
    # Check if order exists
    if order_id not in orders_db:
        print(f"[red]Order not found[/red]")
        raise HTTPException(status_code=404, detail="Order not found")
    
    order_info = orders_db[order_id]
    
    # Only allow user to verify their own orders
    if order_info["username"] != username:
        print(f"[red]✗ Access denied: cannot verify other user's orders[/red]")
        raise HTTPException(status_code=403, detail="Cannot verify other user's orders")
    
    # Verify signature
    is_valid = verify_order_signature(
        order_id=order_id,
        invoice_data=order_info["order_data"],
        signature_b64=order_info["signature"],
        falcon_public_key=falcon_public_key
    )
    
    from datetime import datetime, timezone
    
    return {
        "order_id": order_id,
        "valid": is_valid,
        "signer": "server",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": (
            "Order signature verified — non-repudiation guaranteed"
            if is_valid
            else "Order signature verification failed — order may have been tampered"
        )
    }


if __name__ == "__main__":
    print("\n" + "=" * 76)
    print("Starting Secure Shop API")
    print("=" * 76 + "\n")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
