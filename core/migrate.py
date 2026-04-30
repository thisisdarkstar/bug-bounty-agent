#!/usr/bin/env python3
"""
Database migration script - initializes SQLite database with all tables
Run this once before starting the application
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.database import db_manager


async def migrate():
    """Initialize database with all tables"""
    print("🔧 Starting database migration...")
    
    try:
        # Initialize async database (creates all tables)
        await db_manager.initialize()
        
        print("✅ Database initialized successfully!")
        print(f"📁 Database location: {db_manager.db_path}")
        print("\nTables created:")
        print("  - jobs (scan job tracking)")
        print("  - findings (vulnerability findings)")
        print("  - task_results (tool execution results)")
        print("  - audit_logs (immutable audit trail)")
        print("  - finding_cache (deduplication cache)")
        
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(migrate())
    sys.exit(0 if success else 1)
