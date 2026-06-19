"""
SQLAlchemy models. Sensitive columns stored as AES-256-GCM 
ciphertext following crypto_utils.py conventions.
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()


class User(Base):
    """
    User model with encrypted email field.
    
    Attributes:
        id: Primary key
        username: unique username
        password_hash: hashed password from auth.py
        email_encrypted: AES-256-GCM encrypted email
        created_at: account creation timestamp
    """
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    email_encrypted = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Order(Base):
    """
    Order model with FALCON-signed invoice.
    
    Attributes:
        id: Primary key
        user_id: Foreign key to User
        product_name: name of ordered product
        amount: order amount in currency units
        status: order status (pending, completed, cancelled)
        invoice_signature: FALCON signature over order details
        created_at: order creation timestamp
    """
    __tablename__ = "orders"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    product_name = Column(String, nullable=False)
    amount = Column(Integer, nullable=False)
    status = Column(String, default="pending")
    invoice_signature = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
