#!/usr/bin/env python
"""Initialize PostgreSQL database with tables."""

import os
os.environ["DATABASE_URL"] = "postgresql://postgres@localhost/secure_shop"

try:
    from models import engine, Base
    
    print("Creating tables...")
    Base.metadata.create_all(bind=engine)
    print("✓ All tables created successfully!")
    print("\nDatabase URL: postgresql://postgres@localhost/secure_shop")
    print("Ready to use with FastAPI!")
    
except Exception as e:
    print(f"Error: {str(e)}")
    import traceback
    traceback.print_exc()
