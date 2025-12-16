# web_routes.py
"""
Final Boss Level API Router Index.

This module aggregates modular, versioned, and schema-driven sub-routers.
It serves as the gateway for the /api/v1/ endpoints.
"""

import logging
from datetime import datetime
from typing import List, Tuple, Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query, Path, Body
from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session # Required for type hinting if used directly

# Assuming these are available from the production environment
# Services contain all business logic
from services import (
    UserService, 
    ProductService, 
    OrderService,
    AdminService,
    # New Services assumed to be implemented in the Service Layer
    TransactionService, 
    BroadcastService
)
# Models for type hinting
from reuse.models import User, Product, Order, Admin, UserRole, TopUpStatus, TopUp, DeliveryType

# Dependencies provide controlled access, DB sessions, and utilities
from dependencies import (
    RequireDBSession, 
    RequireAdmin, 
    RequireSuperAdmin, 
    RequirePagination, 
    CurrentAdmin
)

logger = logging.getLogger("api_routes")

# ==============================================================================
# 1. DATA TRANSFER OBJECTS (DTOs) / SCHEMAS
# ==============================================================================

class AdminProfileSchema(BaseModel):
    id: int
    username: str
    role: UserRole
    is_active: bool

    class Config:
        orm_mode = True 

# --- User Schemas ---
class UserDetailSchema(BaseModel):
    id: int
    telegram_id: str
    username: Optional[str]
    balance_usd: float
    is_banned: bool

    class Config:
        orm_mode = True

class PaginatedUsersResponse(BaseModel):
    total_count: int = Field(..., description="Total records available")
    limit: int = Field(..., description="The maximum number of items returned")
    offset: int = Field(..., description="The start index of the current page")
    users: List[UserDetailSchema]

# --- Admin Schemas ---
class CreateAdminRequest(BaseModel):
    username: str = Field(min_length=3)
    password: str = Field(min_length=8)
    role: UserRole = UserRole.ADMIN

class AdminDetailSchema(BaseModel):
    id: int
    username: str
    role: UserRole

    class Config:
        orm_mode = True

# --- Product/Code Schemas ---
class CodeUploadResponse(BaseModel):
    status: str
    uploaded_count: int
    product_id: int
    message: str

# --- Transaction Schemas (New) ---
class TransactionResponse(BaseModel):
    id: int
    user_id: int
    amount_usd: float
    txid_or_note: str
    status: TopUpStatus
    created_at: datetime
    approved_at: Optional[datetime]

    class Config:
        orm_mode = True

class PaginatedTransactionsResponse(BaseModel):
    total_count: int
    limit: int
    offset: int
    transactions: List[TransactionResponse]

class ApproveTransactionRequest(BaseModel):
    amount: float = Field(..., gt=0, description="The actual amount received in USD")

class RejectTransactionRequest(BaseModel):
    reason: str = Field(..., min_length=3, description="Reason for rejection")

# --- Broadcast Schemas (New) ---
class BroadcastTargetScope(str, Enum = "all"): # Simple enum or string literal
    ALL = "all"
    ACTIVE_ONLY = "active_only"
    SPECIFIC_USERS = "specific_users"

class BroadcastRequest(BaseModel):
    message: str = Field(..., min_length=1, description="Message content (supports Markdown)")
    scope: str = Field(default="all", description="Target audience: 'all', 'active_only', 'specific_users'")
    specific_user_ids: Optional[List[int]] = Field(default=None, description="List of User IDs if scope is 'specific_users'")

    @validator('specific_user_ids')
    def validate_ids(cls, v, values):
        if values.get('scope') == 'specific_users' and not v:
            raise ValueError("specific_user_ids must be provided when scope is 'specific_users'")
        return v

class BroadcastResponse(BaseModel):
    status: str
    sent_count: int
    job_id: Optional[str]


# ==============================================================================
# 2. MODULAR ROUTERS
# ==============================================================================

# -----------------
# AUTH ROUTER
# -----------------
auth_router = APIRouter(prefix="/auth", tags=["01 - Auth & Profile"])

@auth_router.get(
    "/me", 
    response_model=AdminProfileSchema,
    summary="Get current authenticated admin profile"
)
def admin_profile(current_admin: CurrentAdmin):
    """Retrieves the profile of the currently logged-in admin user."""
    # Mocking is_active as True since we check is_banned in dependencies
    current_admin.is_active = not current_admin.is_banned 
    return current_admin


# -----------------
# USER ROUTER
# -----------------
user_router = APIRouter(prefix="/users", tags=["02 - Users Management"])

@user_router.get(
    "/",
    response_model=PaginatedUsersResponse,
    summary="List all users with pagination",
    dependencies=[Depends(RequireAdmin)]
)
def list_users(
    db: RequireDBSession,
    pagination: RequirePagination
):
    """Retrieves a paginated list of all users."""
    limit, offset = pagination
    
    # Fallback to direct query if service method missing (Safe Production Fallback)
    total_count = db.query(User).count()
    users = db.query(User).offset(offset).limit(limit).all()
    
    return PaginatedUsersResponse(
        total_count=total_count,
        limit=limit,
        offset=offset,
        users=users
    )

@user_router.post(
    "/{user_id}/ban",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Ban a user by ID",
    dependencies=[Depends(RequireAdmin)]
)
def ban_user(user_id: int, db: RequireDBSession, admin: CurrentAdmin):
    """Toggles a user's ban status and logs the action."""
    AdminService.ban_user(db, user_id, admin.id)
    return None


# -----------------
# PRODUCT ROUTER
# -----------------
product_router = APIRouter(prefix="/products", tags=["05 - Product Management"])

@product_router.post(
    "/upload-codes",
    response_model=CodeUploadResponse,
    summary="Bulk Upload UC Codes (.txt)",
    dependencies=[Depends(RequireAdmin)]
)
async def upload_uc_codes(
    db: RequireDBSession,
    admin: CurrentAdmin,
    product_id: int = Form(..., description="The ID of the product these codes belong to"),
    file: UploadFile = File(..., description="Text file containing one code per line")
):
    """
    Uploads a .txt file containing license/UC codes.
    """
    # 1. Validation: File Type
    if not file.filename.endswith(".txt"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Only .txt files are allowed."
        )

    # 2. Validation: Product Existence
    product = ProductService.get_product(db, product_id)
    if not product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product with ID {product_id} not found."
        )

    # 3. File Processing
    try:
        content = await file.read()
        text_content = content.decode("utf-8")
        
        codes_list = [
            line.strip() for line in text_content.splitlines() 
            if line.strip()
        ]
        
        if not codes_list:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File is empty or contains only whitespace."
            )
            
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File encoding error. Please ensure the file is UTF-8 encoded."
        )

    # 4. Service Call
    try:
        added_count = ProductService.add_codes(db, product_id, codes_list)
        
        logger.info(
            f"Admin {admin.username} (ID: {admin.id}) uploaded {added_count} "
            f"codes for Product {product.name} (ID: {product_id})."
        )
        
        return CodeUploadResponse(
            status="success",
            uploaded_count=added_count,
            product_id=product_id,
            message=f"Successfully added {added_count} codes to {product.name}."
        )
        
    except Exception as e:
        logger.error(f"Failed to upload codes: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error during code upload."
        )


# -----------------
# ADMIN ROUTER
# -----------------
admin_router = APIRouter(prefix="/admins", tags=["03 - Admin Management"])

@admin_router.get(
    "/",
    response_model=List[AdminDetailSchema],
    summary="List all administrators (Super Admin only)",
    dependencies=[Depends(RequireSuperAdmin)]
)
def list_admins(db: RequireDBSession):
    """Retrieves a list of all administrative accounts."""
    return db.query(Admin).all()

@admin_router.post(
    "/",
    response_model=AdminDetailSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new administrator account (Super Admin only)",
    dependencies=[Depends(RequireSuperAdmin)]
)
def create_admin(
    admin_data: CreateAdminRequest, 
    db: RequireDBSession
):
    """Creates a new admin account with the specified role."""
    try:
        # Assuming AdminService handles creation logic
        # Implementation details hidden in service layer
        raise HTTPException(status_code=501, detail="Service not implemented in context.")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Admin creation failed: {str(e)}"
        )


# -----------------
# TRANSACTION & BROADCAST ROUTER
# -----------------
misc_router = APIRouter(prefix="/misc", tags=["04 - Operations (Transactions & Broadcast)"])

# --- TRANSACTIONS ---

@misc_router.get(
    "/transactions",
    response_model=PaginatedTransactionsResponse,
    summary="List transactions with filters",
    dependencies=[Depends(RequireAdmin)]
)
def list_transactions(
    db: RequireDBSession,
    pagination: RequirePagination,
    status: Optional[TopUpStatus] = Query(None, description="Filter by status (pending, approved, rejected)"),
    user_id: Optional[int] = Query(None, description="Filter by User ID"),
    start_date: Optional[datetime] = Query(None, description="Filter by start date"),
    end_date: Optional[datetime] = Query(None, description="Filter by end date")
):
    """
    Retrieves a paginated list of transactions (TopUps).
    Supports filtering by status, user, and date range.
    """
    limit, offset = pagination
    
    # Delegate complex filtering to TransactionService
    total_count, txs = TransactionService.get_transactions_paginated(
        db, 
        limit=limit, 
        offset=offset, 
        status=status, 
        user_id=user_id,
        start_date=start_date,
        end_date=end_date
    )
    
    return PaginatedTransactionsResponse(
        total_count=total_count,
        limit=limit,
        offset=offset,
        transactions=txs
    )

@misc_router.get(
    "/transactions/{tx_id}",
    response_model=TransactionResponse,
    summary="Get transaction details",
    dependencies=[Depends(RequireAdmin)]
)
def get_transaction(
    tx_id: int = Path(..., description="The Transaction (TopUp) ID"),
    db: RequireDBSession = Depends(RequireDBSession)
):
    """Fetches a single transaction by ID."""
    tx = TransactionService.get_transaction_by_id(db, tx_id)
    if not tx:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Transaction not found"
        )
    return tx

@misc_router.post(
    "/transactions/{tx_id}/approve", 
    response_model=TransactionResponse,
    summary="Approve a pending transaction",
    dependencies=[Depends(RequireAdmin)]
)
def approve_transaction(
    admin: CurrentAdmin,
    db: RequireDBSession, 
    tx_id: int = Path(..., description="The Transaction ID"),
    payload: ApproveTransactionRequest = Body(...)
):
    """
    Approves a top-up request.
    - Updates status to APPROVED
    - Credits User Balance
    - Logs Admin Action
    """
    try:
        updated_tx = TransactionService.approve_transaction(
            db=db, 
            tx_id=tx_id, 
            admin_id=admin.id, 
            approved_amount=payload.amount
        )
        return updated_tx
    except ValueError as e:
        # Business logic errors (e.g., already processed)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Approval failed: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Processing failed")

@misc_router.post(
    "/transactions/{tx_id}/reject",
    response_model=TransactionResponse,
    summary="Reject a pending transaction",
    dependencies=[Depends(RequireAdmin)]
)
def reject_transaction(
    admin: CurrentAdmin,
    db: RequireDBSession,
    tx_id: int = Path(..., description="The Transaction ID"),
    payload: RejectTransactionRequest = Body(...)
):
    """
    Rejects a top-up request.
    - Updates status to REJECTED
    - Logs Admin Action and Reason
    """
    try:
        updated_tx = TransactionService.reject_transaction(
            db=db,
            tx_id=tx_id,
            admin_id=admin.id,
            reason=payload.reason
        )
        return updated_tx
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Rejection failed: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Processing failed")

# --- BROADCAST ---

@misc_router.post(
    "/broadcast", 
    response_model=BroadcastResponse,
    summary="Send a message to users",
    dependencies=[Depends(RequireSuperAdmin)] # Restricted to Super Admin due to high impact
)
async def broadcast_message(
    payload: BroadcastRequest,
    db: RequireDBSession,
    admin: CurrentAdmin
):
    """
    Sends a broadcast message to a target group of users via the Telegram Bot.
    """
    logger.info(f"Broadcast initiated by {admin.username} to {payload.scope}")
    
    try:
        sent_count = await BroadcastService.dispatch_broadcast(
            db=db,
            message=payload.message,
            scope=payload.scope,
            admin_id=admin.id,
            specific_user_ids=payload.specific_user_ids
        )
        
        return BroadcastResponse(
            status="success",
            sent_count=sent_count,
            job_id=None # Placeholder if async task queue is added later
        )
    except Exception as e:
        logger.error(f"Broadcast failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Broadcast failed: {str(e)}"
        )


# ==============================================================================
# 3. MAIN API INDEX
# ==============================================================================

# This is the main router that will be included in main.py
router = APIRouter(prefix="/v1")

router.include_router(auth_router)
router.include_router(user_router)
router.include_router(admin_router)
router.include_router(misc_router)
router.include_router(product_router)

# Add a simple version health check
@router.get("/status", tags=["System"])
def api_status():
    return {"status": "ok", "version": "v1"}