# services.py
"""
Admin Service Layer.
Consolidates all admin-side business logic, authentication, and database operations.
Designed for use with FastAPI (dependency injection of AsyncSession).
"""

import os
import hashlib
import logging
import json
import secrets
from datetime import datetime
from typing import List, Optional, Union, Dict, Any, Tuple

from sqlalchemy import select, update, delete, func, and_, desc, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

# Import models
from models import (
    User, Product, ProductCode, Order, TopUp, AdminActionLog,
    BroadcastMessage, Notification, ProductStockAlert,
    UserRole, TopUpStatus, OrderStatus, NotificationType
)

# Configure Logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ==============================================================================
# 1. AUTHENTICATION SERVICE
# ==============================================================================

def verify_admin_login(username: str, password: str) -> bool:
    """
    Verifies admin credentials against environment variables.
    Uses SHA256 hashing for password comparison to avoid storing plain text.
    """
    admin_user = os.getenv("ADMIN_USERNAME", "admin")
    admin_hash = os.getenv("ADMIN_PASSWORD_HASH")

    if not admin_hash:
        logger.warning("ADMIN_PASSWORD_HASH not set in environment. Login disabled.")
        return False

    if username != admin_user:
        return False

    # Hash the provided password
    input_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # Use constant_time_compare to prevent timing attacks
    return secrets.compare_digest(input_hash, admin_hash)

# ==============================================================================
# 2. INTERNAL HELPERS
# ==============================================================================

async def _log_admin_action(
    db: AsyncSession, 
    admin_id: int, 
    action: str, 
    details: Optional[str] = None
):
    """
    Internal helper to log admin actions to the database.
    """
    try:
        log_entry = AdminActionLog(
            admin_id=admin_id,
            action=action,
            details=details
        )
        db.add(log_entry)
        # We allow the caller to commit the transaction
    except Exception as e:
        logger.error(f"Failed to create admin log: {e}")

# ==============================================================================
# 3. USER MANAGEMENT
# ==============================================================================

async def get_all_users(db: AsyncSession, skip: int = 0, limit: int = 100) -> List[User]:
    """Retrieves a paginated list of users."""
    stmt = select(User).offset(skip).limit(limit).order_by(desc(User.created_at))
    result = await db.execute(stmt)
    return result.scalars().all()

async def get_user_by_id(db: AsyncSession, user_id: int) -> Optional[User]:
    """Retrieves a single user by ID."""
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()

async def update_user_balance(
    db: AsyncSession, 
    admin_id: int, 
    user_id: int, 
    new_balance: float
) -> User:
    """Updates a user's balance and logs the action."""
    user = await get_user_by_id(db, user_id)
    if not user:
        raise ValueError(f"User {user_id} not found")

    old_balance = user.balance_usd
    user.balance_usd = new_balance
    
    await _log_admin_action(
        db, admin_id, "update_balance", 
        f"User {user_id}: {old_balance} -> {new_balance}"
    )
    await db.commit()
    await db.refresh(user)
    return user

async def set_user_ban_status(
    db: AsyncSession, 
    admin_id: int, 
    user_id: int, 
    is_banned: bool
) -> User:
    """Bans or Unbans a user."""
    user = await get_user_by_id(db, user_id)
    if not user:
        raise ValueError(f"User {user_id} not found")

    user.is_banned = is_banned
    action = "ban_user" if is_banned else "unban_user"
    
    await _log_admin_action(db, admin_id, action, f"User {user_id}")
    await db.commit()
    await db.refresh(user)
    return user

# ==============================================================================
# 4. TOP-UP MANAGEMENT
# ==============================================================================

async def get_pending_topups(db: AsyncSession) -> List[TopUp]:
    """Fetches all top-ups with PENDING status."""
    stmt = (
        select(TopUp)
        .where(TopUp.status == TopUpStatus.PENDING)
        .order_by(TopUp.created_at)
        .options(selectinload(TopUp.user))
    )
    result = await db.execute(stmt)
    return result.scalars().all()

async def approve_topup(db: AsyncSession, admin_id: int, topup_id: int) -> TopUp:
    """
    Approves a top-up: updates status, credits balance, notifies user, logs action.
    """
    stmt = select(TopUp).where(TopUp.id == topup_id).options(selectinload(TopUp.user))
    result = await db.execute(stmt)
    topup = result.scalar_one_or_none()

    if not topup:
        raise ValueError("TopUp not found")
    if topup.status != TopUpStatus.PENDING:
        raise ValueError("TopUp is not pending")

    # Update TopUp
    topup.status = TopUpStatus.APPROVED
    topup.approved_at = datetime.utcnow()

    # Update Balance
    topup.user.balance_usd += topup.amount_usd

    # Notify User
    notification = Notification(
        type=NotificationType.TOPUP,
        user_id=topup.user_id,
        message=f"Your top-up of ${topup.amount_usd:.2f} has been approved.",
        is_read=False
    )
    db.add(notification)

    # Log Action
    await _log_admin_action(db, admin_id, "approve_topup", f"TopUp {topup_id} (${topup.amount_usd})")
    
    await db.commit()
    await db.refresh(topup)
    return topup

async def reject_topup(db: AsyncSession, admin_id: int, topup_id: int) -> TopUp:
    """Rejects a top-up and logs it."""
    stmt = select(TopUp).where(TopUp.id == topup_id)
    result = await db.execute(stmt)
    topup = result.scalar_one_or_none()

    if not topup:
        raise ValueError("TopUp not found")
    
    topup.status = TopUpStatus.REJECTED
    
    notification = Notification(
        type=NotificationType.TOPUP,
        user_id=topup.user_id,
        message=f"Your top-up of ${topup.amount_usd:.2f} was rejected.",
        is_read=False
    )
    db.add(notification)

    await _log_admin_action(db, admin_id, "reject_topup", f"TopUp {topup_id}")
    await db.commit()
    await db.refresh(topup)
    return topup

# ==============================================================================
# 5. PRODUCT & STOCK MANAGEMENT
# ==============================================================================

async def create_product(
    db: AsyncSession, 
    admin_id: int, 
    name: str, 
    price_usd: float
) -> Product:
    """Creates a new product catalog entry."""
    # Check if name exists to prevent duplicates via this simple endpoint
    stmt = select(Product).where(Product.name == name)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise ValueError(f"Product '{name}' already exists.")

    new_product = Product(name=name, price_usd=price_usd, is_active=True)
    db.add(new_product)
    
    await db.flush()
    await _log_admin_action(db, admin_id, "create_product", f"Product {new_product.id}: {name}")
    
    await db.commit()
    await db.refresh(new_product)
    return new_product

async def add_product_with_codes(
    db: AsyncSession,
    admin_id: int,
    name: str,
    price_usd: float,
    raw_codes: str
) -> Dict[str, Any]:
    """
    UPSERT Logic:
    1. Checks if a product with 'name' exists.
    2. If YES: Updates the price and uses existing ID.
    3. If NO: Creates a new Product.
    4. Parses 'raw_codes', removes duplicates (DB-check), and bulk inserts them.
    
    Returns: Dict with product details and added code count.
    """
    # 1. Check for existing product
    stmt = select(Product).where(Product.name == name)
    result = await db.execute(stmt)
    product = result.scalar_one_or_none()

    action_type = ""
    
    if product:
        # UPSERT: Update existing product
        if product.price_usd != price_usd:
            product.price_usd = price_usd
            action_type = "updated_price"
        else:
            action_type = "existing_product"
    else:
        # CREATE: New product
        product = Product(name=name, price_usd=price_usd, is_active=True)
        db.add(product)
        await db.flush()  # Flush to generate product.id
        action_type = "created_product"

    # 2. Process Codes (Deduplication Logic)
    # Filter empty lines and whitespace
    lines = [line.strip() for line in raw_codes.splitlines() if line.strip()]
    
    added_count = 0
    if lines:
        unique_input_codes = set(lines)
        
        # Check against DB for duplicates (Global Uniqueness per ProductCode model)
        # Using chunks for checking if the list is massive is better, 
        # but for typical file uploads, this IN clause is acceptable.
        stmt_check = select(ProductCode.code).where(ProductCode.code.in_(unique_input_codes))
        result_check = await db.execute(stmt_check)
        existing_codes_in_db = set(result_check.scalars().all())
        
        # Determine valid new codes
        new_codes_to_insert = unique_input_codes - existing_codes_in_db
        
        if new_codes_to_insert:
            db_objects = [
                ProductCode(product_id=product.id, code=code, is_sold=False)
                for code in new_codes_to_insert
            ]
            db.add_all(db_objects)
            added_count = len(db_objects)
    
    # 3. Log and Commit
    log_detail = f"{action_type}, added {added_count} codes"
    await _log_admin_action(db, admin_id, "upsert_product", log_detail)
    
    await db.commit()
    await db.refresh(product)
    
    return {
        "product_id": product.id,
        "name": product.name,
        "price_usd": product.price_usd,
        "status": action_type,
        "codes_added": added_count,
        "duplicates_skipped": len(lines) - added_count if lines else 0
    }

async def update_product(
    db: AsyncSession, 
    admin_id: int, 
    product_id: int, 
    **fields
) -> Product:
    """Updates product fields (name, price, is_active)."""
    product = await db.get(Product, product_id)
    if not product:
        raise ValueError("Product not found")

    for key, value in fields.items():
        if hasattr(product, key):
            setattr(product, key, value)

    await _log_admin_action(db, admin_id, "update_product", f"Product {product_id} updated")
    await db.commit()
    await db.refresh(product)
    return product

async def delete_product(db: AsyncSession, admin_id: int, product_id: int):
    """Deletes a product."""
    product = await db.get(Product, product_id)
    if not product:
        raise ValueError("Product not found")
    
    await db.delete(product)
    await _log_admin_action(db, admin_id, "delete_product", f"Product {product_id}")
    await db.commit()

async def upload_product_codes(
    db: AsyncSession, 
    admin_id: int, 
    product_id: int, 
    raw_text: str
) -> int:
    """
    Adds codes to an EXISTING product ID.
    Reuses the robust deduplication logic.
    """
    # Verify product exists
    product = await db.get(Product, product_id)
    if not product:
        raise ValueError("Product not found")

    # Reuse logic via upsert function or implement directly
    # Implementation directly here for specific endpoint usage:
    
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    if not lines:
        return 0

    unique_input_codes = set(lines)
    
    # Deduplication
    stmt = select(ProductCode.code).where(ProductCode.code.in_(unique_input_codes))
    result = await db.execute(stmt)
    existing_codes = set(result.scalars().all())
    
    new_codes = unique_input_codes - existing_codes
    
    if not new_codes:
        return 0

    db_objects = [
        ProductCode(product_id=product_id, code=code, is_sold=False)
        for code in new_codes
    ]
    db.add_all(db_objects)
    
    count = len(db_objects)
    await _log_admin_action(
        db, admin_id, "add_stock", 
        f"Added {count} codes to Product {product_id}"
    )
    await db.commit()
    return count

async def get_product_stock_count(db: AsyncSession, product_id: int) -> int:
    """Returns the number of unsold codes for a product."""
    stmt = select(func.count()).select_from(ProductCode).where(
        ProductCode.product_id == product_id,
        ProductCode.is_sold == False
    )
    result = await db.execute(stmt)
    return result.scalar() or 0

# ==============================================================================
# 6. ORDER & VIEW LAYER
# ==============================================================================

async def get_all_orders(db: AsyncSession, skip: int = 0, limit: int = 50) -> List[Order]:
    """Fetches paginated orders with user details."""
    stmt = (
        select(Order)
        .options(selectinload(Order.user), selectinload(Order.product))
        .order_by(desc(Order.created_at))
        .offset(skip)
        .limit(limit)
    )
    result = await db.execute(stmt)
    return result.scalars().all()

async def get_orders_by_user(db: AsyncSession, user_id: int) -> List[Order]:
    """Fetches purchase history for a specific user."""
    stmt = (
        select(Order)
        .where(Order.user_id == user_id)
        .options(selectinload(Order.product))
        .order_by(desc(Order.created_at))
    )
    result = await db.execute(stmt)
    return result.scalars().all()

# ==============================================================================
# 7. BROADCAST SYSTEM
# ==============================================================================

async def create_broadcast(
    db: AsyncSession,
    admin_id: int,
    message_text: str,
    target_mode: str = "all",
    target_users: Optional[List[int]] = None
) -> BroadcastMessage:
    """Creates a broadcast record for the bot to pick up."""
    is_all = (target_mode == "all")
    user_ids_str = json.dumps(target_users) if target_users else None

    broadcast = BroadcastMessage(
        message_text=message_text,
        sent_to_all=is_all,
        sent_to_user_ids=user_ids_str
    )
    db.add(broadcast)
    
    await _log_admin_action(db, admin_id, "create_broadcast", f"Target: {target_mode}")
    await db.commit()
    await db.refresh(broadcast)
    return broadcast

# ==============================================================================
# 8. NOTIFICATIONS & ALERTS
# ==============================================================================

async def get_low_stock_products(db: AsyncSession, default_threshold: int = 5) -> List[Dict[str, Any]]:
    """
    Identifies products where unsold count <= threshold.
    Returns a list of dicts with product details and current stock.
    """
    stmt_products = select(Product).where(Product.is_active == True)
    result_products = await db.execute(stmt_products)
    products = result_products.scalars().all()
    
    low_stock_items = []

    for p in products:
        stock = await get_product_stock_count(db, p.id)
        
        # Check for custom threshold
        stmt_alert = select(ProductStockAlert).where(ProductStockAlert.product_id == p.id)
        alert_res = await db.execute(stmt_alert)
        alert_conf = alert_res.scalar_one_or_none()
        
        threshold = alert_conf.threshold if alert_conf else default_threshold
        
        # We return items regardless of low stock for the main inventory view,
        # but the frontend filters or highlights them.
        # Alternatively, strict filtering:
        # if stock <= threshold:
        low_stock_items.append({
            "product_id": p.id,
            "name": p.name,
            "price_usd": p.price_usd,
            "current_stock": stock,
            "threshold": threshold
        })
            
    return low_stock_items

async def configure_stock_alert(
    db: AsyncSession, 
    admin_id: int, 
    product_id: int, 
    threshold: int
) -> ProductStockAlert:
    """Sets a custom low-stock threshold for a product."""
    stmt = select(ProductStockAlert).where(ProductStockAlert.product_id == product_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()

    if alert:
        alert.threshold = threshold
    else:
        alert = ProductStockAlert(product_id=product_id, threshold=threshold)
        db.add(alert)

    await _log_admin_action(db, admin_id, "config_alert", f"Product {product_id} <= {threshold}")
    await db.commit()
    await db.refresh(alert)
    return alert