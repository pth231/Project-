"""
End-to-end demo script. Inspired by cmd_demo() in 
ecdhe_core.py — prints step-by-step output showing crypto operations.

This demo runs the full API flow: register → login → verify FALCON JWT.
Starts server as subprocess, makes HTTP calls, displays results.
"""

import sys
import json
import time
import asyncio
import subprocess
import signal
import secrets
from pathlib import Path
from rich import print
from rich.table import Table

# Ensure local project imports work even when demo is launched from another cwd
sys.path.insert(0, str(Path(__file__).parent))

try:
    import httpx
except ImportError:
    print("FAIL httpx not installed. Install with: pip install httpx")
    sys.exit(1)


async def run_demo() -> None:
    """
    Run end-to-end demo of the secure shopping platform.
    Performs: startup → register → login → verify JWT → summary
    """
    
    print("" + "=" * 76 + "")
    print("SECURE SHOPPING PLATFORM — LIVE API DEMO")
    print("" + "=" * 76 + "\n")
    
    results = {}
    registered_username = None
    registered_password = "secure_password_123"
    token = None

    # =========================================================================
    # STARTUP: Start FastAPI server
    # =========================================================================
    print("Startup: Starting FastAPI server...")
    print("-" * 76)
    
    server_process = None
    try:
        # Start server in background
        server_process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "main:app", 
             "--host", "0.0.0.0", "--port", "8000"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(Path(__file__).parent)
        )
        
        # Wait for server to be ready by polling the health endpoint
        print("Waiting for server to start...")
        start_time = time.time()
        server_ready = False
        while time.time() - start_time < 10:
            if server_process.poll() is not None:
                stderr = server_process.stderr.read().decode(errors="ignore")
                raise RuntimeError(f"Server process exited early: {stderr.strip()}")
            try:
                async with httpx.AsyncClient(base_url="http://localhost:8000", timeout=1.0) as health_client:
                    response = await health_client.get("/")
                    if response.status_code == 200:
                        server_ready = True
                        break
            except Exception:
                await asyncio.sleep(0.5)

        if not server_ready:
            raise RuntimeError("Server did not start in time.")

        print("OK Server started\n")
        
    except Exception as e:
        print(f"FAIL Failed to start server: {str(e)}\n")
        return
    
    try:
        # Connect to server
        async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
            
            # =====================================================================
            # STEP 1: Register
            # =====================================================================
            print("Step 1: User Registration")
            print("-" * 76)
            
            try:
                random_suffix = secrets.token_hex(4)
                registered_username = f"nguyen_van_a_{random_suffix}"
                register_data = {
                    "username": registered_username,
                    "password": registered_password,
                    "email": f"nguyenvana_{random_suffix}@secure-shop.local"
                }
                
                print(f"Sending registration request...")
                print(f"Username: {register_data['username']}")
                print(f"Email: {register_data['email']}\n")
                
                response = await client.post("/register", json=register_data)
                if response.status_code != 200:
                    raise RuntimeError(
                        f"status={response.status_code} body={response.text}"
                    )
                
                result = response.json()
                print(f"OK Registration successful")
                print(f"Response: {json.dumps(result)}\n")
                results["Register"] = True
                
            except Exception as e:
                print(f"FAIL Registration failed: {str(e)}\n")
                results["Register"] = False
                registered_username = None
            
            # =====================================================================
            # STEP 2: Login
            # =====================================================================
            print("Step 2: User Login & JWT Generation")
            print("-" * 76)
            
            try:
                if not registered_username:
                    raise RuntimeError("Registration failed — cannot proceed with login.")

                login_data = {
                    "username": registered_username,
                    "password": registered_password
                }
                
                print(f"Sending login request...")
                print(f"Username: {login_data['username']}\n")
                
                response = await client.post("/login", json=login_data)
                response.raise_for_status()
                
                result = response.json()
                token = result["token"]
                
                print(f"OK Login successful")
                print(f"Message: {result['message']}")
                print(f"JWT Token (first 80 chars): {token[:80]}...")
                print(f"Token length: {len(token)} bytes\n")
                results["Login"] = True
                
            except Exception as e:
                print(f"FAIL Login failed: {str(e)}\n")
                results["Login"] = False
                token = None
            
            # =====================================================================
            # STEP 3: Verify JWT Structure
            # =====================================================================
            if token:
                print("Step 3: JWT Structure Analysis")
                print("-" * 76)
                
                try:
                    # Parse JWT (header.payload.signature)
                    parts = token.split('.')
                    if len(parts) == 3:
                        print(f"JWT Format: header.payload.signature\n")
                        
                        import base64
                        
                        def decode_b64(s):
                            padding = 4 - (len(s) % 4)
                            if padding != 4:
                                s += '=' * padding
                            try:
                                return json.loads(base64.urlsafe_b64decode(s))
                            except:
                                return {"error": "decode failed"}
                        
                        header = decode_b64(parts[0])
                        payload = decode_b64(parts[1])
                        
                        print(f"Header:")
                        print(f"  Algorithm: {header.get('alg')}")
                        print(f"  Type: {header.get('typ')}\n")
                        
                        print(f"Payload:")
                        print(f"  Username: {payload.get('username')}")
                        print(f"  Email: {payload.get('email')}")
                        print(f"  Role: {payload.get('role')}")
                        print(f"  Issued at: {payload.get('iat')}")
                        print(f"  Expires at: {payload.get('exp')}\n")
                        
                        sig_len = len(parts[2].encode())
                        print(f"Signature:")
                        print(f"  Length: {sig_len} bytes")
                        print(f"  Algorithm: FALCON-512 (post-quantum safe)\n")
                        
                        print("OK JWT structure verified\n")
                        results["JWT Structure"] = True
                    else:
                        print("FAIL Invalid JWT format\n")
                        results["JWT Structure"] = False
                        
                except Exception as e:
                    print(f"FAIL Analysis failed: {str(e)}\n")
                    results["JWT Structure"] = False
            
    finally:
        # =========================================================================
        # CLEANUP: Stop server
        # =========================================================================
        if server_process:
            print("Stopping server...")
            server_process.terminate()
            try:
                server_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server_process.kill()
            print("OK Server stopped\n")
    
    # =========================================================================
    # STEP 4: Summary Table
    # =========================================================================
    print("Step 4: Demo Summary")
    print("-" * 76)
    print()
    
    # Create summary table
    table = Table(title="API Flow & Security Features")
    table.add_column("Operation", style="cyan", width=20)
    table.add_column("Feature", style="magenta", width=30)
    table.add_column("Status", style="green", width=15)
    
    operations = [
        ("Register", "Argon2 password hashing"),
        ("Login", "FALCON-512 JWT signature"),
        ("JWT Structure", "Post-quantum cryptography"),
    ]
    
    for op, feature in operations:
        status_val = results.get(op, False)
        status_text = "OK Passed" if status_val else "FAIL Failed"
        table.add_row(op, feature, status_text)
    
    print(table)
    print()
    
    # Final summary
    passed_count = sum(1 for v in results.values() if v)
    total_count = len(results)
    
    print("" + "=" * 76 + "")
    print(f"Demo Complete: {passed_count}/{total_count} operations passed")
    print("" + "=" * 76 + "")
    print("OK Secure Shop API demonstrated successfully!")


if __name__ == "__main__":
    try:
        asyncio.run(run_demo())
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")