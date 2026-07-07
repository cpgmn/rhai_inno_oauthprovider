#!/usr/bin/env python3
"""Diagnostic script to verify OAuth table schema.

Checks:
1. Database type (PostgreSQL vs other)
2. Actual columns in oauth_authorization_codes table
3. Comparison with ORM expectations
"""

import sys
from pathlib import Path

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import inspect, text
from app.db.session import engine
from app.config.settings import settings
from app.models.orm import OAuthAuthorizationCode


def check_database_type():
    """Check if database is PostgreSQL."""
    db_url = str(settings.database_url)
    print("=" * 70)
    print("DATABASE TYPE CHECK")
    print("=" * 70)
    print(f"Database URL: {db_url}")
    
    if "postgresql" in db_url.lower() or "postgres" in db_url.lower():
        print("✓ Database: PostgreSQL")
        return True
    else:
        print("✗ Database: NOT PostgreSQL")
        return False


def check_table_columns():
    """Query actual table columns from database."""
    print("\n" + "=" * 70)
    print("DATABASE TABLE COLUMNS")
    print("=" * 70)
    
    try:
        # Use SQLAlchemy inspector to get table info
        inspector = inspect(engine)
        
        if not inspector.has_table("oauth_authorization_codes"):
            print("✗ Table 'oauth_authorization_codes' does NOT exist")
            return None
        
        print("✓ Table 'oauth_authorization_codes' EXISTS\n")
        print("Actual columns in database:")
        print("-" * 70)
        
        columns = inspector.get_columns("oauth_authorization_codes")
        actual_cols = {}
        for col in columns:
            col_name = col["name"]
            col_type = str(col["type"])
            col_nullable = col.get("nullable", True)
            default = col.get("default")
            
            actual_cols[col_name] = {
                "type": col_type,
                "nullable": col_nullable,
                "default": default
            }
            
            print(f"  • {col_name:25} {col_type:20} nullable={col_nullable}")
        
        return actual_cols
    
    except Exception as e:
        print(f"✗ Error querying table: {e}")
        return None


def check_orm_expectations():
    """Check ORM model expectations."""
    print("\n" + "=" * 70)
    print("ORM MODEL EXPECTATIONS")
    print("=" * 70)
    print("Expected columns from OAuthAuthorizationCode model:")
    print("-" * 70)
    
    orm_cols = {}
    for col in OAuthAuthorizationCode.__table__.columns:
        col_name = col.name
        col_type = str(col.type)
        col_nullable = col.nullable
        
        orm_cols[col_name] = {
            "type": col_type,
            "nullable": col_nullable
        }
        
        print(f"  • {col_name:25} {col_type:20} nullable={col_nullable}")
    
    return orm_cols


def compare_schemas(actual_cols, orm_cols):
    """Compare actual database schema with ORM expectations."""
    print("\n" + "=" * 70)
    print("SCHEMA COMPARISON")
    print("=" * 70)
    
    if actual_cols is None:
        print("✗ Cannot compare: table not found in database")
        return False
    
    all_good = True
    
    # Check for missing columns
    missing_cols = set(orm_cols.keys()) - set(actual_cols.keys())
    if missing_cols:
        print("\n✗ MISSING COLUMNS in database:")
        for col_name in sorted(missing_cols):
            orm_type = orm_cols[col_name]["type"]
            print(f"    • {col_name} ({orm_type})")
        all_good = False
    else:
        print("\n✓ All ORM columns exist in database")
    
    # Check for extra columns
    extra_cols = set(actual_cols.keys()) - set(orm_cols.keys())
    if extra_cols:
        print("\n⚠ EXTRA COLUMNS in database (not in ORM):")
        for col_name in sorted(extra_cols):
            db_type = actual_cols[col_name]["type"]
            print(f"    • {col_name} ({db_type})")
    
    # Check for type mismatches
    type_mismatches = []
    for col_name in orm_cols:
        if col_name in actual_cols:
            orm_type = orm_cols[col_name]["type"]
            db_type = actual_cols[col_name]["type"]
            # Normalize for comparison (e.g., VARCHAR vs String)
            if orm_type.lower().replace("string", "varchar") != db_type.lower().replace("varchar", "string"):
                type_mismatches.append((col_name, orm_type, db_type))
    
    if type_mismatches:
        print("\n⚠ TYPE MISMATCHES:")
        for col_name, orm_type, db_type in type_mismatches:
            print(f"    • {col_name}: ORM expects {orm_type}, DB has {db_type}")
    else:
        print("\n✓ All column types match")
    
    return all_good


def main():
    """Run all diagnostics."""
    try:
        print("\n")
        print("╔" + "═" * 68 + "╗")
        print("║" + "OAUTH TABLE SCHEMA DIAGNOSTIC".center(68) + "║")
        print("╚" + "═" * 68 + "╝")
        
        is_postgres = check_database_type()
        
        if not is_postgres:
            print("\n⚠ Warning: This application is designed for PostgreSQL")
        
        actual_cols = check_table_columns()
        orm_cols = check_orm_expectations()
        
        if actual_cols is not None:
            schemas_match = compare_schemas(actual_cols, orm_cols)
            
            print("\n" + "=" * 70)
            print("SUMMARY")
            print("=" * 70)
            if schemas_match:
                print("✓ Schema is VALID - all columns match ORM expectations")
            else:
                print("✗ Schema is INVALID - there are mismatches (see above)")
                print("\nTo fix missing columns, run:")
                print("  ALTER TABLE public.oauth_authorization_codes")
                print("  ADD COLUMN used boolean NOT NULL DEFAULT FALSE;")
        
        print("\n")
    
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
