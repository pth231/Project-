from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from rich import print

from auth import hash_password, verify_password, create_jwt, verify_jwt
from crypto_utils import generate_falcon_keypair

app = FastAPI(title="Secure Shop API", version="0.1.0")

# In-memory storage
users_db = {}  # {username: {"password_hash": str, "email": str}}

# Generate FALCON keypair for JWT signing on startup
try:
    FALCON_PUBLIC_KEY, FALCON_PRIVATE_KEY = generate_falcon_keypair()
    print("[green]✓ FALCON keypair generated for JWT signing[/green]")
except Exception as e:
    print(f"[red]✗ Failed to generate FALCON keypair: {str(e)}[/red]")
    raise


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
    print(f"\n[bold cyan]=== POST /register ===[/bold cyan]")
    print(f"[yellow]Username:[/yellow] {req.username}")
    print(f"[yellow]Email:[/yellow] {req.email}")
    
    if req.username in users_db:
        print(f"[red]✗ User already exists[/red]\n")
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Hash password
    hashed = hash_password(req.password)
    
    # Store user
    users_db[req.username] = {
        "password_hash": hashed,
        "email": req.email
    }
    
    print(f"[green]✓ User registered successfully[/green]\n")
    return {
        "status": "success",
        "username": req.username,
        "message": "Registration successful"
    }


@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest):
    """
    Login user and return FALCON-signed JWT.
    
    - Verify password
    - Create JWT signed with FALCON
    - Return token
    """
    print(f"\n[bold cyan]=== POST /login ===[/bold cyan]")
    print(f"[yellow]Username:[/yellow] {req.username}")
    
    if req.username not in users_db:
        print(f"[red]✗ User not found[/red]\n")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    user = users_db[req.username]
    
    # Verify password
    if not verify_password(req.password, user["password_hash"]):
        print(f"[red]✗ Login failed[/red]\n")
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Create JWT with FALCON signature
    payload = {
        "username": req.username,
        "email": user["email"],
        "role": "customer"
    }
    token = create_jwt(payload, FALCON_PRIVATE_KEY)
    
    print(f"[green]✓ Login successful[/green]\n")
    return LoginResponse(
        username=req.username,
        token=token,
        message="Login successful - JWT contains FALCON signature"
    )


if __name__ == "__main__":
    print("\n[bold cyan]" + "=" * 76)
    print("Starting Secure Shop API")
    print("=" * 76 + "[/bold cyan]\n")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
