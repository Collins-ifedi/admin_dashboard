# create_tables.py
"""
Database Initialization Script.

Responsibilities:
1. Applies schema to the database (creates tables).
2. Bootstraps the initial Super Admin user if not present.
   (Required because auth.py checks DB for the user after env var validation).
"""

import asyncio
import logging
import os
import sys
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

# Import DB and Models
from db import engine, AsyncSessionLocal
from models import Base, User, UserRole

# ==============================================================================
# LOGGING CONFIG
# ==============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("db_init")

# ==============================================================================
# CONFIGURATION
# ==============================================================================
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
# We need a placeholder ID because User.telegram_id is NOT NULL and Unique.
# Real admins will bind their Telegram ID later or update it via DB.
ADMIN_TELEGRAM_ID = os.getenv("ADMIN_TELEGRAM_ID", "system_admin_01") 

async def create_schema():
    """
    Connects to the DB and creates tables defined in SQLAlchemy models.
    """
    logger.info("🛠  Checking database schema...")
    try:
        async with engine.begin() as conn:
            # create_all checks for existence internally, so this is safe
            await conn.run_sync(Base.metadata.create_all)
        logger.info("✅ Schema applied successfully.")
    except Exception as e:
        logger.critical(f"❌ Failed to create schema: {e}")
        raise

async def bootstrap_admin():
    """
    Ensures the bootstrap admin defined in environment variables exists in the DB.
    Ref: auth.py -> login_for_access_token (Step 2)
    """
    logger.info(f"👤 Verifying bootstrap admin: '{ADMIN_USERNAME}'")

    async with AsyncSessionLocal() as session:
        try:
            # 1. Check if Admin exists
            stmt = select(User).where(User.username == ADMIN_USERNAME)
            result = await session.execute(stmt)
            existing_user = result.scalar_one_or_none()

            if existing_user:
                logger.info("✅ Bootstrap admin already exists. Skipping creation.")
                return

            # 2. Check if the placeholder Telegram ID is already taken (Edge case)
            stmt_tg = select(User).where(User.telegram_id == ADMIN_TELEGRAM_ID)
            result_tg = await session.execute(stmt_tg)
            if result_tg.scalar_one_or_none():
                logger.warning(
                    f"⚠️  Cannot create admin '{ADMIN_USERNAME}'. "
                    f"Telegram ID '{ADMIN_TELEGRAM_ID}' is already in use by another user."
                )
                return

            # 3. Create the Admin User
            logger.info("⚡ Creating initial Super Admin user...")
            new_admin = User(
                username=ADMIN_USERNAME,
                telegram_id=ADMIN_TELEGRAM_ID,
                role=UserRole.SUPER_ADMIN,
                balance_usd=999999.0, # Infinite budget for testing/admin
                is_banned=False,
                language="en"
            )
            
            session.add(new_admin)
            await session.commit()
            logger.info(f"✅ User '{ADMIN_USERNAME}' created with Role: SUPER_ADMIN")

        except IntegrityError as e:
            await session.rollback()
            logger.error(f"❌ Integrity Error during bootstrap: {e}")
        except Exception as e:
            await session.rollback()
            logger.error(f"❌ Unexpected error during user bootstrap: {e}")

async def main():
    """
    Orchestrator function.
    """
    try:
        await create_schema()
        await bootstrap_admin()
    finally:
        # Close the connection pool gracefully
        await engine.dispose()
        logger.info("👋 Database connection closed.")

if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Process cancelled by user.")
    except Exception as e:
        logger.critical(f"Fatal Error: {e}")
        sys.exit(1)