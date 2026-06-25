#!/usr/bin/env python
"""Initialize PostgreSQL database with tables."""

from dotenv import load_dotenv
load_dotenv()

try:
    from models import engine, Base
    
    print("Creating tables...")
    Base.metadata.create_all(bind=engine)
    print("✓ All tables created successfully!")
    print("\nDatabase URL: {0}".format(engine.url))
    print("Ready to use with FastAPI!")
    
except Exception as e:
    print(f"Error: {str(e)}")
    import traceback
    traceback.print_exc()
