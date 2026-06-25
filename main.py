from fastapi import FastAPI, HTTPException, Depends, Request, Security
from fastapi.security import HTTPBearer
from pydantic import BaseModel
import uvicorn
from rich import print
from time import time
from collections import defaultdict

from auth import hash_password, verify_password, create_jwt, verify_jwt, get_current_user, require_role
from crypto_utils import generate_falcon_keypair
from order_service import OrderRequest, create_order_with_signature, verify_order_signature
from models import SessionLocal, User, Order, init_db
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

app = FastAPI(title="Secure Shop API", version="0.1.0")
security = HTTPBearer()

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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
async def startup_event():
    init_db()


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
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    """
    Register a new user.
    
    - Hash password with Argon2
    - Store in-memory
    - Return success message
    """
    print(f"\n=== POST /register ===")
    print(f"Username: {req.username}")
    print(f"Email: {req.email}")
    
    existing_user = db.query(User).filter(User.username == req.username).first()
    if existing_user is not None:
        print(f"FAIL User already exists\n")
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Hash password
    hashed = hash_password(req.password)
    
    # Assign role: admin if username is "admin", otherwise customer
    role = "admin" if req.username == "admin" else "customer"
    
    # Create user record
    user = User(
        username=req.username,
        password_hash=hashed,
        role=role
    )
    user.set_email(req.email)
    
    try:
        db.add(user)
        db.commit()
    except SQLAlchemyError as e:
        db.rollback()
        print(f"FAIL User registration DB error: {str(e)}\n")
        raise HTTPException(status_code=500, detail="Registration failed")
    
    print(f"OK User registered with role: {role}\n")
    return {
        "status": "success",
        "username": req.username,
        "message": "Registration successful"
    }


@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
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
    
    user = db.query(User).filter(User.username == req.username).first()
    if user is None:
        print(f"FAIL User not found\n")
        record_failed_login(req.username)  # Record attempt
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Verify password
    if not verify_password(req.password, user.password_hash):
        print(f"FAIL Login failed\n")
        record_failed_login(req.username)  # Record failed attempt
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Successful login - reset failed attempts
    reset_failed_attempts(req.username)
    
    # Create JWT with FALCON signature
    payload = {
        "username": req.username,
        "email": user.get_email(),
        "role": user.role
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
    falcon_public_key: bytes = Depends(get_falcon_public_key),
    credentials = Security(security),
    db: Session = Depends(get_db)
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
    
    users = db.query(User).all()
    # Return user list without password hashes
    user_list = [
        {
            "username": user.username,
            "email": user.get_email(),
            "role": user.role
        }
        for user in users
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
    falcon_public_key: bytes = Depends(get_falcon_public_key),
    credentials = Security(security),
    db: Session = Depends(get_db)
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
    except Exception as e:
        print(f"[red]✗ Order processing failed: {str(e)}[/red]")
        raise HTTPException(status_code=400, detail=str(e))
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        print(f"[red]✗ User not found for order persistence\n")
        raise HTTPException(status_code=404, detail="User not found")
    
    order = Order(
        order_id=response.order_id,
        user_id=user.id,
        amount=response.total,
        falcon_signature=response.invoice_signature,
        session_key_fingerprint=response.session_key_fingerprint
    )
    order.set_invoice_data(invoice_data)
    
    try:
        db.add(order)
        db.commit()
    except SQLAlchemyError as e:
        db.rollback()
        print(f"[red]✗ Order persistence failed: {str(e)}[/red]")
        raise HTTPException(status_code=500, detail="Order persistence failed")
    
    print(f"\n[green]✓ Order stored in database[/green]")
    
    return response.dict()


@app.get("/orders/{order_id}/verify")
async def verify_order(
    order_id: str,
    request: Request,
    falcon_public_key: bytes = Depends(get_falcon_public_key),
    credentials = Security(security),
    db: Session = Depends(get_db)
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
    
    order = db.query(Order).filter(Order.order_id == order_id).first()
    if order is None:
        print(f"[red]Order not found[/red]")
        raise HTTPException(status_code=404, detail="Order not found")
    
    user = db.query(User).filter(User.username == username).first()
    if user is None or order.user_id != user.id:
        print(f"[red]✗ Access denied: cannot verify other user's orders[/red]")
        raise HTTPException(status_code=403, detail="Cannot verify other user's orders")
    
    invoice_data = order.get_invoice_data()
    signature_b64 = order.falcon_signature
    
    # Verify signature
    is_valid = verify_order_signature(
        order_id=order_id,
        invoice_data=invoice_data,
        signature_b64=signature_b64,
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
