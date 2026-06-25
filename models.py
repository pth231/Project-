"""
SQLAlchemy models with column-level AES-256-GCM encryption.
Production-ready database schema for Secure Shop API.

Models:
- User: with encrypted email field
- Order: with encrypted invoice_data and FALCON signature
"""

import os
import json
import secrets
import base64
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from rich import print

from crypto_utils import aes_encrypt, aes_decrypt

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable not configured")

engine = create_engine(
    DATABASE_URL,
    echo=False,  # Set to True for SQL logging
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ============================================================================
# AES-256-GCM ENCRYPTION HELPERS
# ============================================================================

# Load AES key from environment - should be 32 bytes (256 bits)
AES_KEY_HEX = os.getenv("AES_KEY")
if not AES_KEY_HEX:
    raise RuntimeError("AES_KEY environment variable not configured")

AES_KEY = bytes.fromhex(AES_KEY_HEX)

print(f"[green]✓ AES-256 key loaded: {len(AES_KEY)} bytes[/green]")


def encrypt_field(value: str) -> str:
    """
    Encrypt a string value using AES-256-GCM.
    
    Args:
        value: plaintext string to encrypt
        
    Returns:
        JSON string with {ciphertext, nonce, tag}
    """
    plaintext_bytes = value.encode()
    encrypted_dict = aes_encrypt(plaintext_bytes, AES_KEY)
    return json.dumps(encrypted_dict)


def decrypt_field(encrypted_json: str) -> str:
    """
    Decrypt an AES-256-GCM encrypted field.
    
    Args:
        encrypted_json: JSON string with {ciphertext, nonce, tag}
        
    Returns:
        decrypted plaintext string
    """
    encrypted_dict = json.loads(encrypted_json)
    plaintext_bytes = aes_decrypt(
        encrypted_dict["ciphertext"],
        AES_KEY,
        encrypted_dict["nonce"],
        encrypted_dict["tag"]
    )
    return plaintext_bytes.decode()


# ============================================================================
# SQLALCHEMY MODELS
# ============================================================================

class User(Base):
    """
    User model with encrypted email field.
    
    Fields:
    - id: UUID primary key
    - username: unique, indexed, plaintext (needed for lookup)
    - password_hash: Argon2 hash (plaintext in DB)
    - email_encrypted: AES-encrypted JSON {"ciphertext", "nonce", "tag"}
    - role: user role for RBAC (customer, admin, etc.)
    - created_at: timestamp
    """
    __tablename__ = "users"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    username = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    email_encrypted = Column(Text, nullable=False)
    role = Column(String(50), default="customer", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def set_email(self, email: str):
        """Set encrypted email."""
        self.email_encrypted = encrypt_field(email)
    
    def get_email(self) -> str:
        """Get decrypted email."""
        return decrypt_field(self.email_encrypted)
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"


class Order(Base):
    """
    Order model with encrypted invoice data and FALCON signature.
    
    Fields:
    - id: UUID internal primary key
    - order_id: external order identifier used by the API
    - user_id: FK to User.id
    - amount: order total (float)
    - status: pending/paid/cancelled
    - invoice_data_encrypted: AES-encrypted invoice JSON
    - falcon_signature: base64-encoded FALCON signature of invoice hash
    - session_key_fingerprint: fingerprint of the derived session key
    - created_at: timestamp
    """
    __tablename__ = "orders"
    
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    order_id = Column(String(100), unique=True, nullable=False, index=True)
    user_id = Column(PG_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    status = Column(String(50), default="pending", nullable=False, index=True)
    invoice_data_encrypted = Column(Text, nullable=False)
    falcon_signature = Column(Text, nullable=False)
    session_key_fingerprint = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    def set_invoice_data(self, invoice_dict: dict):
        """Set encrypted invoice data."""
        invoice_json = json.dumps(invoice_dict, sort_keys=True)
        self.invoice_data_encrypted = encrypt_field(invoice_json)
    
    def get_invoice_data(self) -> dict:
        """Get decrypted invoice data."""
        invoice_json = decrypt_field(self.invoice_data_encrypted)
        return json.loads(invoice_json)
    
    def __repr__(self):
        return f"<Order(id={self.id}, order_id='{self.order_id}', user_id={self.user_id}, amount={self.amount}, status='{self.status}')>"


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db():
    """
    Create all database tables if they don't exist.
    
    Call this on application startup to ensure schema is initialized.
    """
    print("\n[cyan]=== DATABASE INITIALIZATION ===[/cyan]")
    try:
        # Create all tables
        Base.metadata.create_all(bind=engine)
        print("[green]✓ Database tables created successfully[/green]")
        
        # List created tables
        table_names = [table.name for table in Base.metadata.tables.values()]
        print(f"[dim]Tables: {', '.join(table_names)}[/dim]")
        
    except Exception as e:
        print(f"[red]✗ Database initialization failed: {str(e)}[/red]")
        raise


# Demo for testing
if __name__ == "__main__":
    print("[cyan bold]=== MODELS DEMO ===[/cyan bold]\n")
    
    # Initialize DB
    init_db()
    
    # Test encryption/decryption
    print(f"\n[cyan]=== AES-256 FIELD ENCRYPTION ===[/cyan]")
    
    test_email = "alice@example.com"
    encrypted = encrypt_field(test_email)
    print(f"[dim]Original email: {test_email}[/dim]")
    print(f"[dim]Encrypted (first 50 chars): {encrypted[:50]}...[/dim]")
    
    decrypted = decrypt_field(encrypted)
    print(f"[dim]Decrypted email: {decrypted}[/dim]")
    
    if decrypted == test_email:
        print(f"[green]✓ Roundtrip encryption successful[/green]")
    else:
        print(f"[red]✗ Encryption roundtrip failed[/red]")
    
    print("\n[green]Demo complete[/green]")
