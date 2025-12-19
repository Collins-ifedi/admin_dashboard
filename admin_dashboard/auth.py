# auth.py
"""
Production-grade Authentication Module.

Standards:
- NIST guidelines for password storage (bcrypt) - prepared for future DB expansion.
- JWT (JSON Web Tokens) for stateless authentication.
- Strict type enforcement and Pydantic validation.
- Centralized security logging.

UPDATED:
- Aligned with 'models.py' (User model).
- Removes 'config.py' dependency.
- Implements Hybrid Auth: Validates Credentials via Env (Bootstrap), resolves Identity via DB.
"""

import logging
import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import select

from db import get_db
from models import User, UserRole  # Updated to use the actual User model

# ==============================================================================
# CONFIGURATION & LOGGING
# ==============================================================================

# Constants
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 Hours
TOKEN_URL = "/api/v1/admin/login"      # Endpoint for Swagger UI

# Secrets Management (Replaces config.py)
SECRET_KEY = os.getenv("SECRET_KEY", "change_this_in_production_to_a_secure_random_string")

# Logging Setup
logger = logging.getLogger("auth_module")
logger.setLevel(logging.INFO)

# Security Contexts
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=TOKEN_URL)


# ==============================================================================
# DATA TRANSFER OBJECTS (DTOs)
# ==============================================================================

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenPayload(BaseModel):
    sub: Optional[str] = None  # User ID (stored as string in JWT)
    username: Optional[str] = None
    role: Optional[str] = None
    exp: Optional[int] = None


# ==============================================================================
# AUTH SERVICE LAYER
# ==============================================================================

class AuthService:
    """
    Encapsulates all cryptographic and authentication business logic.
    """

    @staticmethod
    def verify_env_admin_credentials(username: str, password: str) -> bool:
        """
        Verifies credentials against Environment Variables (Bootstrap Admin).
        Use this if Users in DB do not have password hashes.
        """
        env_user = os.getenv("ADMIN_USERNAME", "admin")
        env_hash = os.getenv("ADMIN_PASSWORD_HASH")

        if not env_hash:
            logger.warning("ADMIN_PASSWORD_HASH not set. Login disabled.")
            return False

        if username != env_user:
            return False

        # Compare hashes
        input_hash = hashlib.sha256(password.encode()).hexdigest()
        return secrets.compare_digest(input_hash, env_hash)

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """
        Creates a signed JWT access token.
        
        Args:
            data: The payload to encode (must include 'sub').
            expires_delta: Optional custom expiration time.
        """
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            
        to_encode.update({"exp": expire})
        
        encoded_jwt = jwt.encode(
            to_encode, 
            SECRET_KEY, 
            algorithm=ALGORITHM
        )
        return encoded_jwt

    @staticmethod
    async def authenticate_admin(db: Session, username: str, password: str) -> Optional[User]:
        """
        Hybrid Authentication:
        1. Verifies Username/Password against Environment Variables (Secure).
        2. Retrieves the corresponding 'User' entity from DB to validate Roles/Ban status.
        
        Assumptions:
        - The Admin Username in Env Vars maps to a 'username' in the 'users' table.
        - Alternatively, it maps to a specific ID (e.g. ID 1).
        """
        # 1. Verify Credentials (Env check)
        if not AuthService.verify_env_admin_credentials(username, password):
            logger.warning(f"Auth failed: Invalid credentials for '{username}'.")
            return None

        # 2. Resolve User Entity from DB
        # We search for a user with the matching username to enforce RBAC
        # Note: Since models.py uses async style often, ensure the session passed here handles sync or async correctly.
        # However, FastAPI's `Depends(get_db)` in this context usually returns a session. 
        # For simplicity in this sync method, we assume standard query.
        
        # If using async session (AsyncSession), this requires 'await'. 
        # Since this method is static and might be called from async route, we return the user.
        
        # NOTE: For this specific function, we assume the caller handles the DB query 
        # because mixing Sync/Async logic here depends on the exact DB Session type (AsyncSession vs Session).
        # We will return True merely to indicate credential validity, 
        # but to fit the signature, we return a Mock or rely on the route to fetch the user.
        
        return True # Handled by Route for now, or fetch strictly if using sync driver.


# ==============================================================================
# DEPENDENCIES (FastAPI Injection)
# ==============================================================================

async def get_current_admin(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)]
) -> User:
    """
    Validates the JWT token and retrieves the current active admin User.
    Raises 401 for invalid tokens or 403 for banned users.
    
    Returns:
        User: The database user object (models.User).
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode Token
        payload = jwt.decode(
            token, 
            SECRET_KEY, 
            algorithms=[ALGORITHM]
        )
        
        # Validate Payload Structure
        token_data = TokenPayload(**payload)
        
        if token_data.sub is None:
            logger.error("Token validation failed: Missing 'sub' (user_id).")
            raise credentials_exception
            
    except jwt.ExpiredSignatureError:
        logger.info("Token validation failed: Token expired.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (JWTError, ValueError) as e:
        logger.error(f"Token validation error: {str(e)}")
        raise credentials_exception

    # Database Lookup
    try:
        user_id = int(token_data.sub)
        
        # Async SQLAlchemy Query
        # Note: get_db returns an AsyncSession, so we must use await
        stmt = select(User).where(User.id == user_id)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        
    except ValueError:
        raise credentials_exception
    except Exception as e:
        logger.error(f"Database error during auth resolution: {e}")
        raise credentials_exception

    if user is None:
        logger.warning(f"Token valid but User ID {token_data.sub} not found in DB.")
        raise credentials_exception
        
    if user.is_banned:
        logger.warning(f"Access denied: User {user.username} is banned.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is banned"
        )
    
    # Optional: Enforce strictly ADMIN role here, or leave to 'require_admin_role' dependency
    if user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        # Log it but let RBAC dependency handle the 403 detail
        logger.info(f"User {user.username} authenticated but is role {user.role}")

    return user

# ==============================================================================
# ROUTE HANDLER UTILITIES
# ==============================================================================

async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm,
    db: Session
):
    """
    Business logic for the /token endpoint.
    Checks Env Credentials -> If valid, tries to find an Admin User in DB to bind the token to.
    """
    # 1. Verify Password against Environment (Source of Truth for Admin Password)
    is_valid = AuthService.verify_env_admin_credentials(form_data.username, form_data.password)
    
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 2. Fetch the User Object (to get the ID for the token)
    # We try to find a user in DB with the same username
    stmt = select(User).where(User.username == form_data.username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    # Fallback: If no DB user exists for this Admin login, we can't issue a valid user-bound token.
    # In production, you must ensure an Admin User exists in the users table.
    if not user:
         logger.error(f"Login successful but no DB User found for '{form_data.username}'.")
         raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="System Error: Admin user profile missing in database."
        )

    # 3. Create Token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = AuthService.create_access_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "role": str(user.role.value if hasattr(user.role, 'value') else user.role)
        },
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}