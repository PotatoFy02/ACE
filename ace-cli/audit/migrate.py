# audit/migrate.py
"""
Run with:  python -m audit.migrate
Flags:
  --rollback    drop all ACE tables (destructive)
  --check       print table list only, no changes
"""
import asyncio
import argparse
import os
import asyncpg
from audit.models import MIGRATION_SQL, ROLLBACK_SQL


async def run_migration(rollback: bool = False, check: bool = False):
    dsn = os.environ.get("ACE_DATABASE_URL")
    if not dsn:
        raise EnvironmentError("ACE_DATABASE_URL not set")

    conn = await asyncpg.connect(dsn)
    try:
        if check:
            rows = await conn.fetch(
                """
                SELECT tablename FROM pg_tables
                WHERE schemaname = 'public'
                  AND tablename IN ('scans','patches','audit_log')
                ORDER BY tablename
                """
            )
            tables = [r["tablename"] for r in rows]
            print(f"ACE tables present: {tables or 'none'}")
            return

        if rollback:
            confirm = input("Drop all ACE tables? This is irreversible. Type YES: ")
            if confirm.strip() != "YES":
                print("Aborted.")
                return
            await conn.execute(ROLLBACK_SQL)
            print("Rollback complete.")
        else:
            await conn.execute(MIGRATION_SQL)
            print("Migration complete. Tables: scans, patches, audit_log")
    finally:
        await conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ACE PostgreSQL migrations")
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--check",    action="store_true")
    args = parser.parse_args()
    asyncio.run(run_migration(rollback=args.rollback, check=args.check))