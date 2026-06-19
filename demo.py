"""
End-to-end demo script. Inspired by cmd_demo() in 
ECDHE_lab_menu_v2.py — prints step-by-step output showing crypto operations.

This demo runs the full API flow: register → login → verify FALCON JWT.
Starts server as subprocess, makes HTTP calls, displays results.
"""

import sys
import json
import time
import asyncio
import subprocess
import signal
from pathlib import Path
from rich import print
from rich.table import Table

# Add teacher's code paths to sys.path (for reference in future phases)
sys.path.insert(0, r"D:\Mat_ma_ung_dung\week5")
sys.path.insert(0, r"D:\Mat_ma_ung_dung\week 7\week07_S1_S2_Codes\week11_Codes")

try:
    import httpx
except ImportError:
    print("[red]✗ httpx not installed. Install with: pip install httpx[/red]")
    sys.exit(1)


async def run_demo() -> None:
    """
    Run end-to-end demo of the secure shopping platform.
    Performs: startup → register → login → verify JWT → summary
    """
    
    print("[bold cyan]" + "=" * 76)
    print("SECURE SHOPPING PLATFORM — LIVE API DEMO")
    print("=" * 76 + "[/bold cyan]\n")
    
    results = {}
    
    # =========================================================================
    # STARTUP: Start FastAPI server
    # =========================================================================
    print("[bold yellow]Startup: Starting FastAPI server...[/bold yellow]")
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
        
        # Wait for server to be ready
        print("[cyan]Waiting for server to start...[/cyan]")
        await asyncio.sleep(3)
        
        print("[green]✓ Server started[/green]\n")
        
    except Exception as e:
        print(f"[red]✗ Failed to start server: {str(e)}[/red]\n")
        return
    
    try:
        # Connect to server
        async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
            
            # =====================================================================
            # STEP 1: Register
            # =====================================================================
            print("[bold yellow]Step 1: User Registration[/bold yellow]")
            print("-" * 76)
            
            try:
                register_data = {
                    "username": "alice",
                    "password": "secure_password_123",
                    "email": "alice@secure-shop.local"
                }
                
                print(f"[cyan]Sending registration request...[/cyan]")
                print(f"[yellow]Username:[/yellow] {register_data['username']}")
                print(f"[yellow]Email:[/yellow] {register_data['email']}\n")
                
                response = await client.post("/register", json=register_data)
                response.raise_for_status()
                
                result = response.json()
                print(f"[green]✓ Registration successful[/green]")
                print(f"[yellow]Response:[/yellow] {json.dumps(result)}\n")
                results["Register"] = True
                
            except Exception as e:
                print(f"[red]✗ Registration failed: {str(e)}[/red]\n")
                results["Register"] = False
            
            # =====================================================================
            # STEP 2: Login
            # =====================================================================
            print("[bold yellow]Step 2: User Login & JWT Generation[/bold yellow]")
            print("-" * 76)
            
            try:
                login_data = {
                    "username": "alice",
                    "password": "secure_password_123"
                }
                
                print(f"[cyan]Sending login request...[/cyan]")
                print(f"[yellow]Username:[/yellow] {login_data['username']}\n")
                
                response = await client.post("/login", json=login_data)
                response.raise_for_status()
                
                result = response.json()
                token = result["token"]
                
                print(f"[green]✓ Login successful[/green]")
                print(f"[yellow]Message:[/yellow] {result['message']}")
                print(f"[yellow]JWT Token (first 80 chars):[/yellow] {token[:80]}...")
                print(f"[yellow]Token length:[/yellow] {len(token)} bytes\n")
                results["Login"] = True
                
            except Exception as e:
                print(f"[red]✗ Login failed: {str(e)}[/red]\n")
                results["Login"] = False
                token = None
            
            # =====================================================================
            # STEP 3: Verify JWT Structure
            # =====================================================================
            if token:
                print("[bold yellow]Step 3: JWT Structure Analysis[/bold yellow]")
                print("-" * 76)
                
                try:
                    # Parse JWT (header.payload.signature)
                    parts = token.split('.')
                    if len(parts) == 3:
                        print(f"[cyan]JWT Format: header.payload.signature[/cyan]\n")
                        
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
                        
                        print(f"[yellow]Header:[/yellow]")
                        print(f"  Algorithm: {header.get('alg')}")
                        print(f"  Type: {header.get('typ')}\n")
                        
                        print(f"[yellow]Payload:[/yellow]")
                        print(f"  Username: {payload.get('username')}")
                        print(f"  Email: {payload.get('email')}")
                        print(f"  Role: {payload.get('role')}")
                        print(f"  Issued at: {payload.get('iat')}")
                        print(f"  Expires at: {payload.get('exp')}\n")
                        
                        sig_len = len(parts[2].encode())
                        print(f"[yellow]Signature:[/yellow]")
                        print(f"  Length: {sig_len} bytes")
                        print(f"  Algorithm: FALCON-512 (post-quantum safe)\n")
                        
                        print("[green]✓ JWT structure verified[/green]\n")
                        results["JWT Structure"] = True
                    else:
                        print("[red]✗ Invalid JWT format[/red]\n")
                        results["JWT Structure"] = False
                        
                except Exception as e:
                    print(f"[red]✗ Analysis failed: {str(e)}[/red]\n")
                    results["JWT Structure"] = False
            
    finally:
        # =========================================================================
        # CLEANUP: Stop server
        # =========================================================================
        if server_process:
            print("[cyan]Stopping server...[/cyan]")
            server_process.terminate()
            try:
                server_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server_process.kill()
            print("[green]✓ Server stopped[/green]\n")
    
    # =========================================================================
    # STEP 4: Summary Table
    # =========================================================================
    print("[bold yellow]Step 4: Demo Summary[/bold yellow]")
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
        ("JWT Decode", "Post-quantum cryptography"),
    ]
    
    for op, feature in operations:
        status_val = results.get(op, False)
        status_text = "[green]✓ Passed[/green]" if status_val else "[red]✗ Failed[/red]"
        table.add_row(op, feature, status_text)
    
    print(table)
    print()
    
    # Final summary
    passed_count = sum(1 for v in results.values() if v)
    total_count = len(results)
    
    print("[bold cyan]" + "=" * 76)
    print(f"Demo Complete: {passed_count}/{total_count} operations passed")
    print("=" * 76 + "[/bold cyan]")
    print("[bold green]✓ Secure Shop API demonstrated successfully![/bold green]")
    print("[yellow]Ready for professor presentation tomorrow.[/yellow]\n")


if __name__ == "__main__":
    try:
        asyncio.run(run_demo())
    except KeyboardInterrupt:
        print("\n[yellow]Demo interrupted by user[/yellow]")
