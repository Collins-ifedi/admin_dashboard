# dependencies.py
"""
Final Boss Level Dependency Utilities for FastAPI.

Responsibilities:
- Defining type aliases for dependency injection.
- Implementing Role-Based Access Control (RBAC) gates with dynamic Super Admin check.
- Providing common utility dependencies (e.g., pagination validation).
"""

import logging
import os
from typing import Annotated, Tuple

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
# Assuming a production utility function 'load_config' exists
# to read values from config.yaml as a fallback.
from utils import load_config  # Assuming utils.py provides load_config

# Import core resolution functions from other production modules
# Assumes Admin, UserRole are defined in reuse.models
from models import User, UserRole
# Assumes get_db is a production-grade session manager
from db import get_db
# Assumes get_current_admin resolves the token, fetches the Admin, and checks for 'is_banned'
from auth import get_current_admin 

logger = logging.getLogger("rbac_dependencies")
logger.setLevel(logging.INFO)

# ==============================================================================
# 1. CORE TYPE ALIASES (For Clean Route Signatures)
# ==============================================================================

# Resolves the current authenticated and active Admin object.
CurrentAdmin = Annotated[User, Depends(get_current_admin)]

# Resolves a database session instance.
RequireDBSession = Annotated[Session, Depends(get_db)]


# ==============================================================================
# 2. RBAC UTILITIES
# ==============================================================================

def get_super_admin_telegram_id() -> str:
    """
    Dynamically reads the Super Admin's Telegram ID from:
    1. Environment variable: SUPER_ADMIN_TELEGRAM_ID
    2. Fallback: config.yaml key 'superUsertelegram_id'
    
    Raises: RuntimeError if ID is not found in either location.
    """
    # 1. Check Environment Variable
    super_admin_id = os.environ.get("SUPER_ADMIN_TELEGRAM_ID")
    if super_admin_id:
        return super_admin_id

    # 2. Check Fallback (config.yaml)
    try:
        config = load_config() # Assumes load_config() fetches configuration
        super_admin_id = config.get("superUsertelegram_id")
        if super_admin_id:
             # Convert to string to match User.telegram_id type, if necessary
            return str(super_admin_id) 
    except Exception as e:
        logger.error(f"Failed to load config for Super Admin ID fallback: {e}")
        
    # 3. Final Fail
    raise RuntimeError(
        "Super Admin Telegram ID not found. Set SUPER_ADMIN_TELEGRAM_ID env var "
        "or 'superUsertelegram_id' in config.yaml."
    )


# ==============================================================================
# 3. ROLE-BASED ACCESS CONTROL (RBAC) GATES
# ==============================================================================

def require_admin_role(admin: CurrentAdmin) -> User:
    """
    Dependency that ensures the authenticated user has at least 'admin' status
    (i.e., 'admin' or 'super_admin').
    """
    if admin.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
        # Log unauthorized attempt for auditing purposes
        logger.warning(
            f"RBAC failed: User {admin.username} (ID: {admin.id}) accessed "
            f"admin resource with insufficient role: {admin.role}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requires Administrator privileges.",
        )
    
    return admin

# This is the primary dependency to use for standard admin routes
RequireAdmin = Annotated[User, Depends(require_admin_role)]


def require_super_admin_by_id(admin: CurrentAdmin) -> User:
    """
    Dependency to strictly restrict access to the dynamically configured Super Admin
    by checking their telegram_id.
    """
    try:
        super_admin_id = get_super_admin_telegram_id()
    except RuntimeError as e:
        logger.critical(f"Super Admin check failed due to missing configuration: {e}")
        # Fail open or closed based on security policy. Closed is safer.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: Super Admin ID is missing.",
        ) from e
        
    # Ensure the admin's telegram_id matches the dynamically loaded Super Admin ID
    if admin.telegram_id != super_admin_id:
        # Log privilege escalation attempt
        logger.warning(
            f"RBAC failed: User {admin.username} (ID: {admin.id}, TelegramID: {admin.telegram_id}) "
            "attempted to access SUPER_ADMIN route (Required ID: {super_admin_id})."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super Admin privileges required.",
        )
    return admin

# This is the primary dependency to use for highly sensitive admin routes
RequireSuperAdmin = Annotated[User, Depends(require_super_admin_by_id)]


# ==============================================================================
# 4. UTILITY DEPENDENCIES
# ==============================================================================

def validate_pagination_params(
    page: int = 1,
    page_size: int = 50,
) -> Tuple[int, int]:
    """
    Dependency to validate and sanitize common pagination query parameters.
    
    Returns: A tuple of (limit, offset) for direct use in SQLAlchemy queries.
    """
    MAX_PAGE_SIZE = 100
    
    if page < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Page number must be 1 or greater.",
        )
    
    if page_size < 1 or page_size > MAX_PAGE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Page size must be between 1 and {MAX_PAGE_SIZE}.",
        )
    
    # Calculate offset for SQLAlchemy queries: OFFSET = (page - 1) * LIMIT
    offset = (page - 1) * page_size
    limit = page_size
    
    return limit, offset

# Use this to inject (limit, offset) into any list endpoint
RequirePagination = Annotated[Tuple[int, int], Depends(validate_pagination_params)]


# ==============================================================================
# SELF TEST
# ==============================================================================

if __name__ == "__main__":
    print("✅ dependencies.py loaded successfully")
    print("This module provides production-grade RBAC and utility dependencies.")