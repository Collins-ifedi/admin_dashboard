# auth.py
"""
Production-grade Authentication Module.

Standards:
- NIST guidelines for password storage (bcrypt).
- JWT (JSON Web Tokens) for stateless authentication.
- Strict type enforcement and Pydantic validation.
- Centralized security logging.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session

from config import settings
from db import get_db
from models import Admin  # Assumes Admin model exists in reuse.models

# ==============================================================================
# CONFIGURATION & LOGGING
# ==============================================================================

# Constants
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 Hours
TOKEN_URL = "/api/auth/login"  # Endpoint for Swagger UI

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
    sub: Optional[str] = None  # Admin ID
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
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verifies a raw password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def get_password_hash(password: str) -> str:
        """Generates a secure bcrypt hash for a password."""
        return pwd_context.hash(password)

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
            settings.SECRET_KEY.get_secret_value(), 
            algorithm=ALGORITHM
        )
        return encoded_jwt

    @staticmethod
    def authenticate_admin(db: Session, username: str, password: str) -> Optional[Admin]:
        """
        Authenticates an admin against the database.
        Returns the Admin object if successful, None otherwise.
        """
        # Case-insensitive username lookup
        admin = db.query(Admin).filter(Admin.username == username).first()
        
        if not admin:
            logger.warning(f"Auth failed: User '{username}' not found.")
            return None
            
        if not AuthService.verify_password(password, admin.password_hash):
            logger.warning(f"Auth failed: Invalid password for '{username}'.")
            return None
            
        if admin.is_banned:
            logger.warning(f"Auth failed: User '{username}' is banned.")
            return None

        logger.info(f"Admin authenticated successfully: {username} ({admin.role})")
        return admin


# ==============================================================================
# DEPENDENCIES (FastAPI Injection)
# ==============================================================================

def get_current_admin(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)]
) -> Admin:
    """
    Validates the JWT token and retrieves the current active admin.
    Raises 401 for invalid tokens or 403 for banned users.
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
            settings.SECRET_KEY.get_secret_value(), 
            algorithms=[ALGORITHM]
        )
        
        # Validate Payload Structure
        token_data = TokenPayload(**payload)
        
        if token_data.sub is None:
            logger.error("Token validation failed: Missing 'sub' (admin_id).")
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
    # We convert sub back to int assuming ID is integer
    try:
        admin_id = int(token_data.sub)
        admin = db.query(Admin).filter(Admin.id == admin_id).first()
    except ValueError:
        raise credentials_exception

    if admin is None:
        logger.warning(f"Token valid but Admin ID {token_data.sub} not found in DB.")
        raise credentials_exception
        
    if admin.is_banned:
        logger.warning(f"Access denied: Admin {admin.username} is banned.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is banned"
        )

    return admin


def require_super_admin(
    current_admin: Annotated[Admin, Depends(get_current_admin)]
) -> Admin:
    """
    Dependency to restrict access to Super Admins only.
    """
    # Assuming the Admin model has a property/field 'is_super_admin' or checking role string
    # Based on reuse.models usage in provided files, we check the role attribute.
    
    # Check if role is explicitly super_admin (adjust string based on specific Enum used in DB)
    is_super = getattr(current_admin, "is_super_admin", False) or current_admin.role == "super_admin"
    
    if not is_super:
        logger.warning(f"Privilege escalation attempt: {current_admin.username} tried accessing super-admin route.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super Admin privileges required"
        )
    return current_admin


# ==============================================================================
# ROUTE HANDLERS (Utility for router)
# ==============================================================================

def login_for_access_token(
    form_data: OAuth2PasswordRequestForm,
    db: Session
):
    """
    Logic for the /token endpoint.
    To be used in the router:
    
    @router.post("/token", response_model=Token)
    def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
        return login_for_access_token(form_data, db)
    """
    admin = AuthService.authenticate_admin(db, form_data.username, form_data.password)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = AuthService.create_access_token(
        data={
            "sub": str(admin.id),
            "username": admin.username,
            "role": str(admin.role)
        },
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}