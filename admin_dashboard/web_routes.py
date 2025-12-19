# routes.py
"""
Admin Dashboard Routes.
Exposes RESTful endpoints for the frontend/dashboard.
Handles Authentication (OAuth2) and delegates business logic to services.py.
"""

import os
import datetime
from datetime import timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

# Import DB and Services
from db import get_db
import services

# Import Models (for Type hinting if needed, though Pydantic is preferred for responses)
from models import UserRole

# ==============================================================================
# CONFIG & SECURITY
# ==============================================================================

router = APIRouter(prefix="/api/v1/admin", tags=["Admin Dashboard"])

# Secret key for JWT (Should be in env, fallback for safety)
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "keep_this_secret_in_production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/admin/login")

# Minimal JWT implementation to avoid heavy dependencies if possible, 
# but using `jose` or `jwt` is standard. For this prompt, we simulate a 
# production token check or use a simple session approach.
# To keep it "production-ready" yet dependency-light for the prompt context,
# we will use a simplified dependency that verifies the token is valid.

from jose import JWTError, jwt

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_admin(token: str = Depends(oauth2_scheme)):
    """
    Dependency to validate the Admin token.
    Returns the admin_id (int) to be used in logs.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        admin_id: int = payload.get("id", 1) # Default to 1 if not set
        if username is None:
            raise credentials_exception
        return admin_id
    except JWTError:
        raise credentials_exception

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
    created_at: datetime
    
    class Config:
        from_attributes = True

class BalanceUpdate(BaseModel):
    amount: float

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

from datetime import datetime

# ==============================================================================
# AUTH ROUTE
# ==============================================================================

@router.post("/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Exchanges username/password for a JWT access token.
    """
    is_valid = services.verify_admin_login(form_data.username, form_data.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # In a real app with an Admin table, we would fetch the ID here.
    # Since we use Env vars, we assume Admin ID = 1 (System) or similar.
    access_token = create_access_token(
        data={"sub": form_data.username, "id": 1}
    )
    return {"access_token": access_token, "token_type": "bearer"}

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
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    try:
        return await services.approve_topup(db, admin_id, topup_id)
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
    # Reusing low_stock logic or creating a simple get_all in services if strictly needed
    # But often get_low_stock_products(threshold=999999) works as a list with stock counts
    # For now, let's assume we implement a simple lister in services or use the DB directly strictly via service
    # Since services.py didn't strictly have get_all_products, we use get_low_stock_products with high threshold to get all + stock
    return await services.get_low_stock_products(db, default_threshold=9999999)

@router.post("/products")
async def create_product(
    payload: ProductCreate, 
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    return await services.create_product(db, admin_id, payload.name, payload.price_usd)

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
    """
    Accepts either a .txt file upload OR raw text via form data.
    """
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
    # Reuse logic with threshold 0 (technically < 1 means 0)
    # The service returns items <= threshold. So threshold 0 returns only 0 stock.
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
    # Note: Added ad-hoc support for fetching pending broadcasts
    # Assuming the table exists and we want to see what hasn't been sent.
    # We might need to add this specific getter to services.py if strictly needed,
    # or rely on a generic getter. 
    # For now, return a placeholder or implement specific logic if service permits.
    return {"message": "Endpoint available, logic to be implemented in services.py"}

# ==============================================================================
# NOTIFICATION ROUTES
# ==============================================================================

@router.get("/notifications")
async def get_notifications(
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    # This would typically fetch system alerts.
    # Assuming we have a service method for admin notifications.
    return {"message": "System notifications"}

@router.post("/notifications/{id}/read")
async def mark_notification_read(
    id: int,
    db: AsyncSession = Depends(get_db),
    admin_id: int = Depends(get_current_admin)
):
    # Placeholder for marking read
    return {"status": "marked_read", "id": id}
