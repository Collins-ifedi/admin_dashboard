# db.py
"""
Production-grade async database layer.
Handles connection creation, SSL contexts for cloud deployment (Render/Heroku),
and session management.

UPDATED: 
- Removed @asynccontextmanager from main dependency to fix FastAPI TypeError.
- Added explicit 'get_manual_session' for scripts/background tasks.
"""

import logging
import ssl
import os
import yaml  # Requires PyYAML: pip install PyYAML
from typing import AsyncGenerator, Any
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
)
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

# Configure logging
logger = logging.getLogger(__name__)

# ==============================================================================
# CONFIGURATION LOADING
# ==============================================================================

def load_config_value(key: str, default: Any = None) -> Any:
    """
    Retrieves configuration values with the following priority:
    1. Environment Variable (Production/Render)
    2. config.yaml file (Local Development)
    3. Default value
    """
    # 1. Check Environment Variable
    env_val = os.getenv(key)
    if env_val is not None:
        return env_val

    # 2. Check config.yaml
    config_path = "config.yaml"
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config_data = yaml.safe_load(f) or {}
                if key in config_data:
                    return config_data[key]
        except Exception as e:
            logger.warning(f"Attempted to read '{key}' from config.yaml but failed: {e}")

    # 3. Return Default
    return default

# Load Database Settings
DATABASE_URL = load_config_value("DATABASE_URL")

# Safe parsing for Boolean settings
_db_echo_val = load_config_value("DB_ECHO", "False")
DB_ECHO = str(_db_echo_val).lower() in ("true", "1", "yes", "on")

DB_POOL_SIZE = int(load_config_value("DB_POOL_SIZE", 20))
DB_MAX_OVERFLOW = int(load_config_value("DB_MAX_OVERFLOW", 10))


# ==============================================================================
# DATABASE URL HANDLING
# ==============================================================================

if not DATABASE_URL:
    raise ValueError(
        "DATABASE_URL not found. Please set it in Environment Variables or config.yaml."
    )

# Fix URL for Async SQLAlchemy (Render/Heroku often provide 'postgres://')
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

# ==============================================================================
# SSL CONTEXT (CRITICAL FOR CLOUD DEPLOYMENT)
# ==============================================================================

connect_args = {}

if "postgresql" in DATABASE_URL:
    try:
        # Create a safe SSL context that ignores self-signed cert errors
        # commonly found in managed DB services (like Render)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        connect_args["ssl"] = ctx
        logger.info("SSL Context enabled for PostgreSQL connection.")
    except Exception as e:
        logger.warning(f"Failed to create SSL context: {e}. Attempting connection without SSL.")

# ==============================================================================
# ASYNC ENGINE & SESSION FACTORY
# ==============================================================================

engine = create_async_engine(
    DATABASE_URL,
    echo=DB_ECHO,
    pool_pre_ping=True,  # Vital for recovering dropped connections
    pool_size=DB_POOL_SIZE,
    max_overflow=DB_MAX_OVERFLOW,
    connect_args=connect_args
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)

# ==============================================================================
# DEPENDENCIES
# ==============================================================================

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Main dependency for FastAPI Routes (Depends(get_db)).
    
    NOTE: Do NOT use @asynccontextmanager here. FastAPI handles the 
    generator context automatically for dependencies.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"DB session error (Depends): {e}")
            raise
        finally:
            await session.close()

@asynccontextmanager
async def get_manual_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager for MANUAL usage (scripts, background tasks).
    
    Usage:
        async with get_manual_session() as db:
            await db.execute(...)
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"DB session error (Manual): {e}")
            raise
        finally:
            await session.close()

# ==============================================================================
# HEALTH CHECK
# ==============================================================================

async def db_healthcheck() -> bool:
    """
    Verifies DB connectivity.
    """
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError as e:
        logger.error(f"DB health check failed: {e}")
        return False