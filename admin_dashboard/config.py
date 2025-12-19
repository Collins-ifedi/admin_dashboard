# config.py
"""
Production-grade Configuration Management.

Standard: 12-Factor App methodology.
Priorities:
1. Environment Variables (Docker/Render)
2. config.yaml (Local/Mounts)
3. Defaults

Includes specific type conversions to ensure compatibility with
db.py (SQLAlchemy) and auth.py (Bcrypt/JWT).
"""

import logging
import os
import yaml
from pathlib import Path
from typing import List, Union, ClassVar, Dict, Any, Tuple, Type

from pydantic import AnyHttpUrl, field_validator, PostgresDsn
from pydantic.types import SecretStr
from pydantic_settings import (
    BaseSettings, 
    PydanticBaseSettingsSource, 
    SettingsConfigDict
)

# Setup basic logging for config loading
logger = logging.getLogger("config")

# Project Directories
BASE_DIR = Path(__file__).resolve().parent
CREDENTIALS_FILE = BASE_DIR / "config.yaml"


class YamlConfigSettingsSource(PydanticBaseSettingsSource):
    """
    Custom Pydantic source to load values from config.yaml.
    """
    def get_field_value(self, field: Any, field_name: str) -> Tuple[Any, str, bool]:
        # Not used directly in this simple implementation but required by abstract base
        return None, field_name, False

    def __call__(self) -> Dict[str, Any]:
        if not CREDENTIALS_FILE.exists():
            logger.info(f"Config file not found at {CREDENTIALS_FILE}. Relying on Environment Variables.")
            return {}
        
        try:
            with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
                yaml_data = yaml.safe_load(f)
                return yaml_data if isinstance(yaml_data, dict) else {}
        except Exception as e:
            logger.error(f"Error parsing YAML config: {e}")
            return {}


class Settings(BaseSettings):
    """
    Application Settings Schema.
    Validates all inputs on startup.
    """
    
    # --- General ---
    PROJECT_NAME: str = "Admin Dashboard"
    ENV: str = "development"  # development, staging, production
    LOG_LEVEL: str = "INFO"
    
    # --- Security ---
    # auth.py expects SecretStr (uses .get_secret_value())
    SECRET_KEY: SecretStr 
    
    # --- Database ---
    # db.py expects str (uses .startswith()), NOT SecretStr
    DATABASE_URL: str

    @field_validator("DATABASE_URL", mode="before")
    def fix_postgres_scheme(cls, v: str) -> str:
        """
        Fixes the connection string provided by some hosting providers (like Render)
        that use 'postgres://' instead of the SQLAlchemy-required 'postgresql://'.
        """
        if v and v.startswith("postgres://"):
            return v.replace("postgres://", "postgresql://", 1)
        return v

    # --- CORS (Cross-Origin Resource Sharing) ---
    # Used in main.py for frontend connection
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[AnyHttpUrl]:
        """Parses a comma-separated string (common in Env Vars) into a list."""
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # --- Business Logic / Payment Configs (Required by services.py) ---
    # These default to dummy values to prevent crash, but should be set in Prod.
    PAYMENT_BINANCE_ID: str = "NOT_CONFIGURED"
    PAYMENT_BYBIT_UID: str = "NOT_CONFIGURED"
    PAYMENT_USDT_ADDR: str = "NOT_CONFIGURED"
    
    LOW_STOCK_THRESHOLD: int = 5

    # --- Pydantic Config ---
    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        extra="ignore"
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        """
        Defines the priority of configuration sources.
        
        Priority (High to Low):
        1. Constructor arguments (init_settings)
        2. Environment Variables (env_settings) <- Critical for Render/Docker
        3. YAML Config File (YamlConfigSettingsSource)
        4. .env file (dotenv_settings)
        5. Defaults
        """
        return (
            init_settings,
            env_settings,
            YamlConfigSettingsSource(settings_cls),
            dotenv_settings,
            file_secret_settings,
        )

# Instantiate Global Settings
try:
    settings = Settings()
    
    # Mask sensitive data for logging
    safe_db_url = "configured" if settings.DATABASE_URL else "missing"
    logger.info(f"Configuration loaded for ENV: {settings.ENV} | DB: {safe_db_url}")
    
except Exception as e:
    logger.critical(f"🔥 FATAL: Configuration Validation Failed.\n{e}")
    raise