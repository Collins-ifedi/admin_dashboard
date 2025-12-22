# web_routes.py
"""
Admin Dashboard Routes.
Exposes RESTful endpoints for the frontend/dashboard.
Handles Authentication (OAuth2) and delegates business logic to services.py.
"""

import os
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

# Import DB and Services
from db import get_db
import services
import auth  # IMPORTED: Production Auth Module
import models # Needed for type hinting in dependency

# ==============================================================================
# CONFIG & SECURITY
# ==============================================================================

router = APIRouter(prefix="/api/v1/admin", tags=["Admin Dashboard"])

async def get_current_admin(
    user: models.User = Depends(auth.get_current_admin)
) -> int:
    """
    Dependency to validate the Admin token using the production auth module.
    
    Adapts the auth.get_current_admin (which returns a User object) 
    to return an integer ID, maintaining compatibility with existing 
    service functions in this file.
    """
    return user.id

# ==============================================================================
# SCHEMAS (Pydantic Models)
# ==============================================================================

class Token(BaseModel):
    access_token: str
    token_type: str

class UserResponse(BaseModel):
    id: int
    telegram_id: str
    username: Optional[str]
    balance_usd: float
    role: str
    is_banned: bool
    created_at: services.datetime # Using datetime from services import or standard lib
    
    class Config:
        from_attributes = True

class BalanceUpdate(BaseModel):
    amount: float

# NEW SCHEMA: Handles the payload from the operations.html approve modal
class ApproveTopupRequest(BaseModel):
    actual_amount: float

class ProductCreate(BaseModel):
    name: str
    price_usd: float

class ProductUpdate(BaseModel):
    name: Optional[str] = None
    price_usd: Optional[float] = None
    is_active: Optional[bool] = None

class BroadcastCreate(BaseModel):
    message: str
    target: str = "all" # "all", "active"
    user_ids: Optional[List[int]] = None

# ==============================================================================
# AUTH ROUTE
# ==============================================================================

@router.post("/login", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """
    Exchanges username/password for a JWT access token.
    Delegates strictly to the production-grade auth.py module.
    """
    return await auth.login_for_access_token(form_data, db)

@router.post("/logout")
async def logout():
    """Client-side logout (clearing token)."""
    return {"message": "Successfully logged out"}

# ==============================================================================
# USER ROUTES
# ==============================================================================

@router.get("/users", response_model=List[UserResponse])
async def read_users(
    skip: int = 0, 
    limit: int = 100, 
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    return await services.get_all_users(db, skip, limit)

@router.get("/users/{user_id}", response_model=UserResponse)
async def read_user(
    user_id: int, 
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    user = await services.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.post("/users/{user_id}/ban")
async def ban_user(
    user_id: int, 
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    try:
        return await services.set_user_ban_status(db, admin_id, user_id, is_banned=True)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/users/{user_id}/unban")
async def unban_user(
    user_id: int, 
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    try:
        return await services.set_user_ban_status(db, admin_id, user_id, is_banned=False)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/users/{user_id}/balance")
async def update_balance(
    user_id: int, 
    payload: BalanceUpdate,
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    try:
        return await services.update_user_balance(db, admin_id, user_id, payload.amount)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# ==============================================================================
# ORDER ROUTES
# ==============================================================================

@router.get("/orders")
async def read_orders(
    skip: int = 0, 
    limit: int = 50, 
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    return await services.get_all_orders(db, skip, limit)

@router.get("/orders/user/{user_id}")
async def read_user_orders(
    user_id: int, 
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    return await services.get_orders_by_user(db, user_id)

# ==============================================================================
# TOP-UP ROUTES
# ==============================================================================

@router.get("/topups/pending")
async def read_pending_topups(
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    return await services.get_pending_topups(db)

@router.post("/topups/{topup_id}/approve")
async def approve_topup(
    topup_id: int, 
    payload: ApproveTopupRequest,  # UPDATED: Accepts the actual_amount body
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    """
    Approves a top-up request using the actual amount confirmed by the admin.
    """
    try:
        # Pass payload.actual_amount to the service
        return await services.approve_topup(db, admin_id, topup_id, payload.actual_amount)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/topups/{topup_id}/reject")
async def reject_topup(
    topup_id: int, 
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    try:
        return await services.reject_topup(db, admin_id, topup_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# ==============================================================================
# PRODUCT ROUTES
# ==============================================================================

@router.get("/products")
async def list_products(
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    return await services.get_low_stock_products(db, default_threshold=9999999)

@router.post("/products")
async def create_product(
    name: str = Form(...),
    price_usd: float = Form(...),
    file: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    """
    Creates or Upserts a product.
    """
    raw_codes = ""
    if file:
        try:
            content_bytes = await file.read()
            raw_codes = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=400, 
                detail="Invalid file encoding. Please ensure the file is a UTF-8 encoded text file."
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error reading file: {str(e)}")

    try:
        result = await services.add_product_with_codes(
            db, admin_id, name, price_usd, raw_codes
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

@router.put("/products/{product_id}")
async def update_product(
    product_id: int, 
    payload: ProductUpdate,
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    try:
        return await services.update_product(
            db, admin_id, product_id, 
            **payload.dict(exclude_unset=True)
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.delete("/products/{product_id}")
async def delete_product(
    product_id: int, 
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    try:
        await services.delete_product(db, admin_id, product_id)
        return {"status": "success", "message": "Product deleted"}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/products/{product_id}/upload-codes")
async def upload_codes(
    product_id: int,
    file: Optional[UploadFile] = File(None),
    text_content: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    content = ""
    if file:
        content_bytes = await file.read()
        content = content_bytes.decode("utf-8")
    elif text_content:
        content = text_content
    else:
        raise HTTPException(status_code=400, detail="No file or text provided")

    count = await services.upload_product_codes(db, admin_id, product_id, content)
    return {"status": "success", "added_count": count}

# ==============================================================================
# STOCK ROUTES
# ==============================================================================

@router.get("/stock/low")
async def get_low_stock(
    threshold: int = 5,
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    return await services.get_low_stock_products(db, threshold)

@router.get("/stock/out")
async def get_out_of_stock(
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    return await services.get_low_stock_products(db, threshold=0)

# ==============================================================================
# BROADCAST ROUTES
# ==============================================================================

@router.post("/broadcast")
async def send_broadcast(
    payload: BroadcastCreate,
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    return await services.create_broadcast(
        db, admin_id, payload.message, payload.target, payload.user_ids
    )

@router.get("/broadcast/pending")
async def get_pending_broadcasts(
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    return {"message": "Endpoint available, logic to be implemented in services.py"}

# ==============================================================================
# NOTIFICATION ROUTES
# ==============================================================================

@router.get("/notifications")
async def get_notifications(
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    return {"message": "System notifications"}

@router.post("/notifications/{id}/read")
async def mark_notification_read(
    id: int,
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    return {"status": "marked_read", "id": id}