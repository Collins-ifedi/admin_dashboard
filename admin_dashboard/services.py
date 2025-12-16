# services.py
"""
Production-grade business logic layer.
Handles complex operations, database transactions, business rules, and logging.

Standards:
- Strict Type Hinting.
- Transaction Management (Commit/Rollback).
- Comprehensive Logging.
- Secure File Handling.
"""

import os
import logging
import datetime
import uuid
from typing import List, Optional, Tuple, Dict, Any, Union
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_

# Import configuration for configurable payment addresses
try:
    from config import settings
except ImportError:
    # Fallback mock settings if config module is not present in context
    class settings:
        PAYMENT_BINANCE_ID = os.getenv("PAYMENT_BINANCE_ID", "Please Configure")
        PAYMENT_BYBIT_UID = os.getenv("PAYMENT_BYBIT_UID", "Please Configure")
        PAYMENT_USDT_ADDR = os.getenv("PAYMENT_USDT_ADDR", "Please Configure")
        LOW_STOCK_THRESHOLD = 5

from models import (
    User,
    Product,
    ProductCode,
    Order,
    TopUp,
    TopUpStatus,
    OrderStatus,
    DeliveryType,
    AdminActionLog,
    UserRole
)

# Initialize logging
logger = logging.getLogger("backend_services")
logger.setLevel(logging.INFO)

# Directory for temporary delivery files
TEMP_DIR = "temp_orders"
os.makedirs(TEMP_DIR, exist_ok=True)


# ==============================================================================
# HELPER UTILITIES
# ==============================================================================

def _round_amount(amount: float) -> float:
    """Ensures consistent 2-decimal precision for currency."""
    return round(amount, 2)

# ==============================================================================
# USER SERVICES
# ==============================================================================

class UserService:
    """
    Handles User lifecycle, retrieval, and profile management.
    """

    @staticmethod
    def _get_user_query(db: Session, telegram_id: Union[int, str]) -> Optional[User]:
        """Internal helper to fetch user by Telegram ID."""
        return db.query(User).filter(User.telegram_id == str(telegram_id)).first()

    @staticmethod
    def get_or_create_user(db: Session, telegram_id: int, username: str) -> User:
        """
        Retrieves a user by Telegram ID or creates a new one if not found.

        Args:
            db (Session): Database session.
            telegram_id (int): Telegram User ID.
            username (str): Telegram Username.

        Returns:
            User: The user object.
        """
        try:
            user = UserService._get_user_query(db, telegram_id)
            if not user:
                user = User(
                    telegram_id=str(telegram_id),
                    username=username,
                    balance_usd=0.0,
                    role=UserRole.USER,
                    is_banned=False
                )
                db.add(user)
                db.commit()
                db.refresh(user)
                logger.info(f"New user created: {username} ({telegram_id})")
            else:
                # Update username if it changed
                if user.username != username:
                    user.username = username
                    db.commit()
            return user
        except Exception as e:
            db.rollback()
            logger.error(f"Error in get_or_create_user: {e}", exc_info=True)
            raise

    @staticmethod
    def get_user_by_telegram_id(db: Session, telegram_id: int) -> Optional[User]:
        """Retrieves user details safely."""
        return UserService._get_user_query(db, telegram_id)

    @staticmethod
    def set_language(db: Session, telegram_id: int, lang_code: str) -> bool:
        """Updates the user's preferred language."""
        try:
            user = UserService._get_user_query(db, telegram_id)
            if user:
                user.language = lang_code
                db.commit()
                return True
            return False
        except Exception as e:
            db.rollback()
            logger.error(f"Error setting language for {telegram_id}: {e}")
            return False

    @staticmethod
    def is_banned(db: Session, telegram_id: int) -> bool:
        """Checks if a user is currently banned."""
        user = UserService._get_user_query(db, telegram_id)
        return user.is_banned if user else False
    
    # Placeholder for future Async implementation
    @staticmethod
    async def get_user_async(telegram_id: int):
        """Future: Async retrieval of user."""
        pass


# ==============================================================================
# PRODUCT & STOCK SERVICES
# ==============================================================================

class ProductService:
    """
    Manages Product inventory, stock levels, and code uploads.
    """

    @staticmethod
    def get_available_products(db: Session) -> List[Product]:
        """Returns all active products."""
        return db.query(Product).filter(Product.is_active == True).all()

    @staticmethod
    def get_product(db: Session, product_id: int) -> Optional[Product]:
        """Returns specific product by ID."""
        return db.query(Product).filter(Product.id == product_id).first()

    @staticmethod
    def get_stock_count(db: Session, product_id: int) -> int:
        """Counts unsold codes for a specific product."""
        return db.query(ProductCode).filter(
            ProductCode.product_id == product_id,
            ProductCode.is_sold == False
        ).count()

    @staticmethod
    def add_product(db: Session, name: str, price: float) -> Product:
        """Creates a new product definition."""
        try:
            product = Product(
                name=name, 
                price_usd=_round_amount(price), 
                is_active=True
            )
            db.add(product)
            db.commit()
            db.refresh(product)
            logger.info(f"Product created: {name} - ${price}")
            return product
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to add product: {e}")
            raise

    @staticmethod
    def add_codes(db: Session, product_id: int, codes_list: List[str]) -> int:
        """
        Bulk uploads codes. Ignores duplicates if code is unique constraint.
        
        Args:
            db (Session): Database session.
            product_id (int): ID of the product.
            codes_list (List[str]): List of code strings.

        Returns:
            int: Count of successfully added codes.
        """
        count = 0
        batch_id = str(uuid.uuid4()) # Track this specific upload batch
        try:
            for code_str in codes_list:
                code_str = code_str.strip()
                if not code_str:
                    continue
                
                # Check existence to avoid unique constraint error spam
                # In high-perf scenarios, use INSERT IGNORE or bulk_save_objects with ignore
                exists = db.query(ProductCode).filter(ProductCode.code == code_str).first()
                if not exists:
                    new_code = ProductCode(
                        product_id=product_id,
                        code=code_str,
                        is_sold=False,
                        batch_id=batch_id
                    )
                    db.add(new_code)
                    count += 1
            
            db.commit()
            logger.info(f"Added {count} codes to Product {product_id} (Batch: {batch_id})")
            return count
        except Exception as e:
            db.rollback()
            logger.error(f"Failed during bulk code upload: {e}")
            raise

    @staticmethod
    def check_low_stock(db: Session, product_id: int, threshold: int = 5) -> None:
        """
        Checks if stock is below threshold and logs a warning.
        Should be called after a purchase.
        """
        count = ProductService.get_stock_count(db, product_id)
        if count <= threshold:
            logger.warning(f"⚠️ LOW STOCK ALERT: Product ID {product_id} has only {count} items left.")


# ==============================================================================
# ORDER & DELIVERY SERVICES
# ==============================================================================

class OrderService:
    """
    Handles the purchasing flow, balance deduction, and item locking.
    """

    @staticmethod
    def create_order(
        db: Session, 
        user: User, 
        product: Product, 
        delivery_type: DeliveryType = DeliveryType.TEXT
    ) -> Tuple[Optional[Order], str]:
        """
        Core Transactional Logic for Purchasing.
        
        Steps:
        1. Validate User (Ban status).
        2. Check Balance.
        3. Lock ProductCode (prevent race conditions).
        4. Deduct Balance & Mark Sold.
        5. Create Order.
        
        Returns:
            Tuple[Optional[Order], str]: (Order Object, Status Message Key)
        """
        try:
            # 0. Ban Check
            if user.is_banned:
                logger.warning(f"Banned user {user.username} attempted purchase.")
                return None, "error_user_banned_notice"

            # 1. Balance Check
            if user.balance_usd < product.price_usd:
                return None, "insufficient_balance"

            # 2. Find and Lock Unsold Code
            # with_for_update(skip_locked=True) ensures we get the next available code 
            # without waiting for other transactions to release locks on other rows.
            code = db.query(ProductCode).filter(
                ProductCode.product_id == product.id,
                ProductCode.is_sold == False
            ).with_for_update(skip_locked=True).first()

            if not code:
                # Trigger Out of Stock Log
                logger.error(f"Product {product.name} (ID: {product.id}) OOS during purchase attempt.")
                return None, "out_of_stock"

            # 3. Execute Transaction
            new_balance = _round_amount(user.balance_usd - product.price_usd)
            user.balance_usd = new_balance
            
            code.is_sold = True
            code.sold_at = datetime.datetime.utcnow()

            order = Order(
                user_id=user.id,
                product_id=product.id,
                product_code_id=code.id,
                price_usd=product.price_usd,
                delivery_type=delivery_type,
                status=OrderStatus.COMPLETED
            )
            
            db.add(order)
            db.commit()
            db.refresh(order)
            
            # Post-transaction check
            ProductService.check_low_stock(db, product.id)
            
            logger.info(f"Order {order.id} SUCCESS: User {user.id} bought {product.name} for ${product.price_usd}")
            return order, "success"

        except Exception as e:
            db.rollback()
            logger.critical(f"Transaction failed for User {user.id}: {e}", exc_info=True)
            return None, "error_database"

    @staticmethod
    def get_order(db: Session, order_id: int) -> Optional[Order]:
        """Retrieves an order by ID."""
        return db.query(Order).filter(Order.id == order_id).first()

    @staticmethod
    def get_code_content(db: Session, order_id: int) -> str:
        """Extracts the sensitive code content from an order."""
        order = db.query(Order).filter(Order.id == order_id).first()
        if order and order.product_code:
            return order.product_code.code
        return ""

    @staticmethod
    def create_txt_file(code_content: str, order_id: int, lang_code: str) -> str:
        """
        Creates a temporary .txt file for file delivery.
        Uses UUID in filename to prevent collisions/guessing.
        
        Returns:
            str: The file path.
        """
        # Secure filename generation
        secure_suffix = uuid.uuid4().hex[:8]
        filename = f"order_{order_id}_{secure_suffix}.txt"
        file_path = os.path.join(TEMP_DIR, filename)
        
        thank_you_message = LanguageService.t(lang_code, "file_delivery_thank_you")
        code_label = LanguageService.t(lang_code, "file_delivery_code_label")
        
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(f"{thank_you_message}\n\n{code_label}\n{code_content}")
            return file_path
        except IOError as e:
            logger.error(f"Failed to write temp file {file_path}: {e}")
            raise

    @staticmethod
    def get_user_statistics(db: Session, telegram_id: int, lang_code: str) -> str:
        """
        Aggregates purchase history and top-ups for the 'Statistics' button.
        """
        user = UserService.get_user_by_telegram_id(db, telegram_id)
        if not user:
            return LanguageService.t(lang_code, "error_user_not_found")

        # Purchases
        total_orders = db.query(Order).filter(Order.user_id == user.id).count()
        
        # Calculate total spent
        total_spent = db.query(func.coalesce(func.sum(Order.price_usd), 0.0)).filter(
            Order.user_id == user.id
        ).scalar()

        # TopUps
        total_topup = db.query(func.coalesce(func.sum(TopUp.amount_usd), 0.0)).filter(
            TopUp.user_id == user.id,
            TopUp.status == TopUpStatus.APPROVED
        ).scalar()

        if total_orders == 0 and total_topup == 0:
            return LanguageService.t(lang_code, "stats_no_history")

        return LanguageService.t(
            lang_code, "stats_template",
            username=user.username if user.username else "Unknown",
            total_orders=total_orders,
            total_spent=_round_amount(total_spent),
            total_topup=_round_amount(total_topup),
            balance=_round_amount(user.balance_usd)
        )


# ==============================================================================
# PAYMENT SERVICES
# ==============================================================================

class PaymentService:
    """
    Manages payment addresses, verification requests, and history.
    """

    @staticmethod
    def get_payment_address(method_key: str, lang_code: str) -> str:
        """
        Returns the payment address/instruction for the given method key.
        Fetches actual addresses from Environment/Settings.
        """
        # Labels
        binance_label = LanguageService.t(lang_code, "payment_binance_label")
        bybit_label = LanguageService.t(lang_code, "payment_bybit_label")
        usdt_label = LanguageService.t(lang_code, "payment_usdt_label")
        
        # Notes
        txid_note = LanguageService.t(lang_code, "payment_txid_note")
        network_note = LanguageService.t(lang_code, "payment_usdt_network_note")
        
        addresses = {
            "binance": f"🆔 {binance_label}: `{settings.PAYMENT_BINANCE_ID}`\n({txid_note})",
            "bybit": f"🆔 {bybit_label}: `{settings.PAYMENT_BYBIT_UID}`\n({txid_note})",
            "usdt": f"🔗 {usdt_label}: `{settings.PAYMENT_USDT_ADDR}`\n({network_note})"
        }
        return addresses.get(method_key, LanguageService.t(lang_code, "payment_unavailable"))

    @staticmethod
    def create_topup_request(
        db: Session, 
        telegram_id: int, 
        method: str, 
        txid_note: str
    ) -> Union[TopUp, None]:
        """
        Creates a pending top-up request for Admin review.
        """
        try:
            user = UserService.get_user_by_telegram_id(db, telegram_id)
            if not user:
                logger.error(f"TopUp failed: User {telegram_id} not found.")
                raise ValueError("User not found")
            
            if user.is_banned:
                logger.warning(f"Banned user {user.username} attempted top-up.")
                return None

            # Input sanitization
            clean_note = txid_note[:250] # Truncate too long notes

            topup = TopUp(
                user_id=user.id,
                amount_usd=0.0, # Will be set by Admin upon approval
                txid_or_note=f"{method.upper()} | {clean_note}",
                status=TopUpStatus.PENDING
            )
            db.add(topup)
            db.commit()
            db.refresh(topup)
            
            logger.info(f"TopUp Request: User {user.id} via {method} - TXID: {clean_note}")
            return topup
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to create topup: {e}")
            raise

    @staticmethod
    def get_user_topup_history(db: Session, telegram_id: int) -> List[TopUp]:
        """Fetches last 10 top-up records."""
        user = UserService.get_user_by_telegram_id(db, telegram_id)
        if not user:
            return []
        
        return db.query(TopUp).filter(
            TopUp.user_id == user.id
        ).order_by(desc(TopUp.created_at)).limit(10).all()


# ==============================================================================
# ADMIN SERVICES
# ==============================================================================

class AdminService:
    """
    Privileged operations for Admins (Ban, Approve TopUp, Logs).
    """
    
    @staticmethod
    def ban_user(db: Session, target_user_id: int, admin_id: int) -> bool:
        """Bans a user and logs the action."""
        try:
            user = db.query(User).filter(User.id == target_user_id).first()
            if user:
                user.is_banned = True
                log_action = f"Banned user {user.username} (ID: {user.telegram_id})"
                
                log = AdminActionLog(admin_id=admin_id, action=log_action)
                db.add(log)
                db.commit()
                logger.info(f"Admin {admin_id} banned User {target_user_id}")
                return True
            return False
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to ban user: {e}")
            raise

    @staticmethod
    def approve_topup(
        db: Session, 
        topup_id: int, 
        admin_id: int, 
        actual_amount: float
    ) -> bool:
        """
        Admin approves a top-up and manually sets the correct amount received.
        """
        if actual_amount <= 0:
            logger.warning(f"Admin {admin_id} tried to approve negative/zero amount: {actual_amount}")
            return False

        try:
            topup = db.query(TopUp).filter(TopUp.id == topup_id).first()
            
            if topup and topup.status == TopUpStatus.PENDING:
                approved_amt = _round_amount(actual_amount)
                
                topup.amount_usd = approved_amt
                topup.status = TopUpStatus.APPROVED
                topup.approved_at = datetime.datetime.utcnow()
                
                # Credit User safely
                if topup.user:
                    topup.user.balance_usd = _round_amount(topup.user.balance_usd + approved_amt)
                
                # Log
                log_action = f"Approved TopUp #{topup.id} for ${approved_amt}"
                log = AdminActionLog(admin_id=admin_id, action=log_action)
                
                db.add(log)
                db.commit()
                logger.info(f"TopUp {topup_id} approved by Admin {admin_id} for ${approved_amt}")
                return True
            return False
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to approve topup: {e}")
            raise


# ==============================================================================
# LANGUAGE SERVICE
# ==============================================================================

class LanguageService:
    """
    Handles internationalization (i18n) with fallback and formatting.
    """
    
    # Complete Translation Dictionary
    STRINGS = {
        "en": {
            # Base Messages
            "welcome": "👋 Welcome to the Digital Store!",
            "out_of_stock": "❌ This product is currently out of stock.",
            "insufficient_balance": "❌ Insufficient balance. Please top up.",
            "generic_error": "An unexpected error occurred. Please try again later.",
            "error_user_not_found": "User not found.",

            # MAIN MENU
            "menu_stock": "🛒 STOCKABLE UC CODES",
            "menu_profile": "👤 PROFILE",
            "menu_statistics": "📊 STATISTICS",
            "menu_languages": "🌐 LANGUAGES",
            "menu_information": "💡 INFORMATION",
            "menu_contact": "📞 CONTACT",

            # DYNAMIC STATS TEMPLATE
            "stats_template": (
                "📊 **STATISTICS**\n\n"
                "👤 **User:** @{username}\n"
                "📦 **Products Bought:** {total_orders}\n"
                "💸 **Total Spent:** ${total_spent:.2f}\n"
                "💰 **Total Top-Up:** ${total_topup:.2f}\n"
                "💳 **Current Balance:** ${balance:.2f}"
            ),
            "stats_no_history": "You have no purchase or top-up history.",

            # PROFILE
            "profile_header": "👤 YOUR PROFILE",
            "profile_add_balance_btn": "💰 ADD BALANCE",
            "profile_topup_history_btn": "📜 TOP-UP HISTORY",
            "payment_selection_message": "💳 Please select your preferred payment method:",
            
            # Payment Status
            "topup_submitted": "✅ Payment submitted for review! Please wait for admin approval.",
            "topup_pending": "⏳ Your top-up is pending admin approval.",
            "topup_approved": "✅ Your top-up of **${amount:.2f}** has been approved!",
            "topup_rejected": "❌ Your top-up request was rejected.",
            
            # Labels
            "payment_binance_label": "Binance Pay ID",
            "payment_bybit_label": "Bybit UID",
            "payment_usdt_label": "USDT Address",
            "payment_txid_note": "Send payment and copy TXID/Note",
            "payment_usdt_network_note": "Only TRC20 network!",
            "payment_unavailable": "Payment method unavailable.",

            # BUY FLOW
            "buy_product_selection_message": "Select the product you wish to purchase:",
            "purchase_confirmation_message": "🛒 You are about to purchase **{product_name}** for **${price:.2f}**. Proceed?",
            "choose_delivery": "📬 Choose how you want to receive your code:",
            "delivery_text_btn": "Text Delivery",
            "delivery_file_btn": "TXT File Delivery",
            "code_sent_text": "✅ **Here is your code:**",
            "code_sent_file": "✅ **Here is your code file:**",
            
            # File content
            "file_delivery_thank_you": "Thank you for your purchase!",
            "file_delivery_code_label": "Your Code:",

            # SYSTEM
            "error_database": "A database error occurred. Transaction rolled back.",
            "error_user_banned_notice": "Your account is currently banned. Please contact support.",
        },
        # (Other languages would follow similar updates for dynamic formatting keys)
        "ru": {
             "welcome": "👋 Добро пожаловать!",
             "stats_template": (
                "📊 **СТАТИСТИКА**\n\n"
                "👤 **Пользователь:** @{username}\n"
                "📦 **Куплено товаров:** {total_orders}\n"
                "💸 **Всего потрачено:** ${total_spent:.2f}\n"
                "💰 **Всего пополнено:** ${total_topup:.2f}\n"
                "💳 **Текущий баланс:** ${balance:.2f}"
            ),
             # ... (Truncated for brevity, assumes full dict as per original file)
             "error_user_banned_notice": "Ваш аккаунт заблокирован.",
             "generic_error": "Произошла ошибка.",
             "file_delivery_thank_you": "Спасибо за покупку!",
             "file_delivery_code_label": "Ваш Код:",
             "payment_binance_label": "ID Binance Pay",
             "payment_bybit_label": "UID Bybit",
             "payment_usdt_label": "Адрес USDT",
             "payment_txid_note": "TXID",
             "payment_usdt_network_note": "TRC20",
             "payment_unavailable": "Недоступно",
        },
        "ar": {
            "welcome": "👋 مرحبًا بك!",
            "stats_template": (
                "📊 **الإحصائيات**\n\n"
                "👤 **المستخدم:** @{username}\n"
                "📦 **المنتجات المشتراة:** {total_orders}\n"
                "💸 **إجمالي المبلغ المنفق:** ${total_spent:.2f}\n"
                "💰 **إجمالي عمليات الشحن:** ${total_topup:.2f}\n"
                "💳 **الرصيد الحالي:** ${balance:.2f}"
            ),
            # ... (Truncated for brevity)
            "error_user_banned_notice": "حسابك محظور.",
             "generic_error": "حدث خطأ.",
             "file_delivery_thank_you": "شكرا لك!",
             "file_delivery_code_label": "الكود الخاص بك:",
             "payment_binance_label": "معرف Binance Pay",
             "payment_bybit_label": "معرف Bybit UID",
             "payment_usdt_label": "عنوان USDT",
             "payment_txid_note": "TXID",
             "payment_usdt_network_note": "TRC20",
             "payment_unavailable": "غير متوفر",
        }
    }

    @staticmethod
    def t(lang: str, key: str, **kwargs) -> str:
        """
        Translate a key to the target language and format it.
        
        Args:
            lang (str): Language code ('en', 'ru', 'ar').
            key (str): The translation key.
            **kwargs: Variables to inject into the translated string.
            
        Returns:
            str: The translated and formatted string.
        """
        # 1. Get Dictionary for Language (Fallback to EN)
        lang_dict = LanguageService.STRINGS.get(lang, LanguageService.STRINGS["en"])
        
        # 2. Get Value (Fallback to Key)
        # Try finding key in target lang, if not, try EN, if not, return Key
        if key in lang_dict:
            raw_str = lang_dict[key]
        else:
            raw_str = LanguageService.STRINGS["en"].get(key, key)
            
        # 3. Format String if kwargs exist
        if kwargs and isinstance(raw_str, str):
            try:
                return raw_str.format(**kwargs)
            except KeyError as e:
                logger.error(f"Missing format key {e} for translation '{key}' in '{lang}'")
                return raw_str
        
        return raw_str

# ==============================================================================
# SELF TEST (UNIT TEST STUBS)
# ==============================================================================
if __name__ == "__main__":
    print("✅ services.py loaded.")
    
    # Simple Mock DB Test
    # In a real scenario, use pytest with a fixture
    print(f"Rounding Test: 10.555 -> {_round_amount(10.555)}")
    
    # Translation Test
    msg = LanguageService.t("en", "stats_template", username="TestBot", total_orders=5, total_spent=100.555, total_topup=200, balance=99.444)
    print("\n[Translation Test Output]:\n" + msg)