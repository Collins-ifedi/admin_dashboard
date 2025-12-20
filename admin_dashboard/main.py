# main.py
"""
Admin Dashboard Backend Entry Point.

Responsibilities:
- Serves the FastAPI application.
- Securely serves frontend HTML files.
- Mounts API routes.
- AUTOMATIC DEPLOYMENT: Executes schema creation and admin bootstrapping on startup.
"""

import os
import logging
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, status, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles

# Import Local Modules
from db import db_healthcheck
from web_routes import router as api_router

# Import Initialization Logic from your updated create_tables.py
from create_tables import create_schema, bootstrap_admin

# ==============================================================================
# LOGGING & CONFIG
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s",
)
logger = logging.getLogger("main")

# ==============================================================================
# LIFESPAN (STARTUP/SHUTDOWN)
# ==============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages application startup and shutdown events.
    This replaces the need to manually run scripts during deployment.
    """
    # --- STARTUP ---
    logger.info("🚀 Initializing Admin Dashboard Services...")

    try:
        # 1. Database Schema Synchronization
        # Ensures all tables (orders, products, etc.) exist.
        await create_schema()
        
        # 2. Admin Bootstrapping
        # Even if your telegram_bot script does this, having it here 
        # prevents the Web API from failing if the bot hasn't run yet.
        await bootstrap_admin()
        
        # 3. Connection Verification
        if await db_healthcheck():
            logger.info("✅ Database is reachable and initialized.")
        else:
            logger.warning("⚠️ Database check returned False. check your DB_URL.")

    except Exception as e:
        logger.critical(f"🔥 Deployment Initialization Failed: {e}")
        # In production, we want the container to restart if init fails.
        raise e

    yield  # --- Application is now live and serving requests ---

    # --- SHUTDOWN ---
    logger.info("🛑 Shutting down backend...")


# ==============================================================================
# FASTAPI INSTANCE
# ==============================================================================

app = FastAPI(
    title="Admin Dashboard",
    lifespan=lifespan,
    docs_url="/docs"
)

# ==============================================================================
# MIDDLEWARE
# ==============================================================================

# GZip for faster loading of large JSON lists (users/orders)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# CORS configuration
origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================================
# ROUTING & STATIC FILES
# ==============================================================================

# API Routes
app.include_router(api_router)

# Mount static assets (CSS/JS) if directory exists
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse, tags=["Frontend"])
async def read_root():
    """Serves index.html."""
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return HTMLResponse("<h1>Dashboard</h1><p>Frontend index.html missing.</p>", status_code=404)

@app.get("/{page_name}", response_class=HTMLResponse, tags=["Frontend"])
async def serve_pages(page_name: str):
    """Dynamically serves page.html (e.g., /users -> users.html)."""
    safe_name = os.path.basename(page_name)
    file_path = f"{safe_name}"

    if os.path.exists(file_path) and os.path.isfile(file_path):
        return FileResponse(file_path)
    
    raise HTTPException(status_code=404, detail="Page not found")

# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=True)
