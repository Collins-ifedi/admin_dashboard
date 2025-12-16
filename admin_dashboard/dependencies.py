# dependencies.py
"""
Final Boss Level Dependency Utilities for FastAPI.

Responsibilities:
- Defining type aliases for dependency injection.
- Implementing Role-Based Access Control (RBAC) gates.
- Providing common utility dependencies (e.g., pagination validation).
"""

import logging
from typing import Annotated, Tuple

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

# Import core resolution functions from other production modules
# Assumes Admin, UserRole are defined in reuse.models
from models import Admin, UserRole
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
CurrentAdmin = Annotated[Admin, Depends(get_current_admin)]

# Resolves a database session instance.
RequireDBSession = Annotated[Session, Depends(get_db)]


# ==============================================================================
# 2. ROLE-BASED ACCESS CONTROL (RBAC) GATES
# ==============================================================================

def require_admin_role(admin: CurrentAdmin) -> Admin:
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
RequireAdmin = Annotated[Admin, Depends(require_admin_role)]


def require_super_admin_role(admin: CurrentAdmin) -> Admin:
    """
    Dependency to strictly restrict access to Super Admins only.
    """
    if admin.role != UserRole.SUPER_ADMIN:
        # Log privilege escalation attempt
        logger.warning(
            f"RBAC failed: User {admin.username} (ID: {admin.id}) "
            "attempted to access SUPER_ADMIN route."
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super Admin privileges required.",
        )
    return admin

# This is the primary dependency to use for highly sensitive admin routes
RequireSuperAdmin = Annotated[Admin, Depends(require_super_admin_role)]


# ==============================================================================
# 3. UTILITY DEPENDENCIES
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