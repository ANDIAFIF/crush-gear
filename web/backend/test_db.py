"""Test script to initialize database and verify tables."""

import sys
from pathlib import Path

# Add parent directory to path so we can import app modules
sys.path.insert(0, str(Path(__file__).parent))

from app.database import init_db, engine
from sqlalchemy import inspect


def test_database_creation():
    """Initialize database and verify all tables exist."""
    print("Initializing database...")
    init_db()

    inspector = inspect(engine)
    tables = inspector.get_table_names()

    expected_tables = [
        "scans",
        "tool_executions",
        "hosts",
        "ports",
        "urls",
        "vulnerabilities",
        "tool_outputs"
    ]

    print(f"\n✓ Database created at: {Path(__file__).parent / 'crushgear.db'}")
    print(f"\nTables created ({len(tables)}):")
    for table in tables:
        status = "✓" if table in expected_tables else "?"
        print(f"  {status} {table}")

    missing = set(expected_tables) - set(tables)
    if missing:
        print(f"\n✗ Missing tables: {missing}")
        return False

    print("\n✓ All expected tables created successfully!")

    # Show columns for each table
    print("\n" + "="*60)
    print("TABLE SCHEMAS:")
    print("="*60)
    for table in sorted(tables):
        print(f"\n{table}:")
        columns = inspector.get_columns(table)
        for col in columns:
            nullable = "NULL" if col['nullable'] else "NOT NULL"
            print(f"  - {col['name']:<20} {str(col['type']):<20} {nullable}")

    return True


if __name__ == "__main__":
    success = test_database_creation()
    sys.exit(0 if success else 1)
