# main.py
"""
Admin Dashboard Backend Entry Point.

Responsibilities:
- Serves the FastAPI application.
- Securely serves frontend HTML files from the root directory without exposing source code.
- Mounts API routes.
- Manages Database Lifespan.
"""

import os
import logging
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, status, HTTPException
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles

# Import Local Modules
# We use the previously defined 'db' for health checks
from db import db_healthcheck
# We import the router. Assuming 'web_routes.py' serves as the 'routes' module.
from web_routes import router as api_router

# ==============================================================================
# LOGGING & CONFIG
# ==============================================================================

# Setup Logger
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
    Verifies Database connectivity before accepting traffic.
    """
    # --- STARTUP ---
    logger.info("🚀 Starting Admin Dashboard Backend...")

    # Database Health Check
    is_db_connected = await db_healthcheck()
    if is_db_connected:
        logger.info("✅ Database connection established.")
    else:
        logger.critical("🔥 Database connection FAILED. API may be unstable.")
        # In strict environments, you might raise an exception here to crash the pod/service
        # raise RuntimeError("Database connection failed on startup.")

    yield  # Application runs here

    # --- SHUTDOWN ---
    logger.info("🛑 Shutting down...")


# ==============================================================================
# FASTAPI INSTANCE
# ==============================================================================

app = FastAPI(
    title="Telegram Bot Admin Dashboard",
    description="Backend API and Static File Server for the Admin Panel.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs", # Keep enabled for Admin convenience, or set to None for strict prod
    redoc_url=None
)


# ==============================================================================
# MIDDLEWARE
# ==============================================================================

# 1. Performance Timing Header
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = f"{process_time:.4f}s"
    return response

# 2. GZip Compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# 3. CORS (Cross-Origin Resource Sharing)
# Configurable via env var, defaults to allowing all for the dashboard context
origins = os.getenv("BACKEND_CORS_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================================================================
# API ROUTING
# ==============================================================================

# Mount the API Router from web_routes.py
# Requests will look like: /api/v1/admin/users
app.include_router(api_router)


# ==============================================================================
# STATIC FILE & FRONTEND SERVING
# ==============================================================================

# 1. Serve 'assets' or 'static' folder if it exists (for CSS/JS images)
# We check if directory exists to avoid errors if user hasn't created it yet.
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")


# 2. Dynamic HTML Serving (The "Frontend")
# We do NOT mount the root directory ("/") as StaticFiles because that would 
# expose sensitive files like main.py, .env, or config.yaml.
# Instead, we manually serve specific HTML files.

@app.get("/", response_class=HTMLResponse, tags=["Frontend"])
async def read_root():
    """Serves the main index.html file."""
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return HTMLResponse(
        content="<h1>Admin Dashboard</h1><p>index.html not found.</p>", 
        status_code=404
    )

@app.get("/{page_name}", response_class=HTMLResponse, tags=["Frontend"])
async def serve_pages(page_name: str):
    """
    Dynamically serves HTML files from the root directory.
    Example: GET /users -> Serves users.html
    
    Security: Strictly filters for .html extension to prevent reading source code.
    """
    # Sanitize: Ensure we only look for the filename, prevent path traversal
    safe_name = os.path.basename(page_name)
    file_path = f"{safe_name}.html"

    if os.path.exists(file_path) and os.path.isfile(file_path):
        return FileResponse(file_path)
    
    # Return 404 if file doesn't exist or isn't an HTML file
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, 
        detail=f"Page '{safe_name}' not found"
    )


# ==============================================================================
# HEALTH CHECK (Kubernetes/Docker Probe)
# ==============================================================================

@app.get("/health", tags=["System"])
async def health_check():
    """Simple health probe."""
    return {"status": "ok", "timestamp": time.time()}


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    import uvicorn
    
    # Retrieve host/port from env or default to standard
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    
    uvicorn.run("main:app", host=host, port=port, reload=True)