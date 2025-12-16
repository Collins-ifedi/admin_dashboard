# admin_dashboard/backend/main.py
"""
Final Boss Level FastAPI Entry Point.

Standards:
- Modern Lifespan (Startup/Shutdown) management.
- Comprehensive Middleware stack (CORS, GZip, Performance Timing).
- Global Exception Handling for standardized error responses.
- Modular Router aggregation.
"""

import time
import logging
from contextlib import asynccontextmanager
from typing import Request

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

# Configuration and Local Imports
from config import settings
from db import init_db, db_healthcheck
from web_routes import router as api_v1_router

# ==============================================================================
# 1. LOGGING CONFIGURATION
# ==============================================================================
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s",
)
logger = logging.getLogger("admin_dashboard_core")


# ==============================================================================
# 2. LIFESPAN MANAGEMENT (Modern Startup/Shutdown)
# ==============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles application startup and shutdown events.
    Replaces deprecated @app.on_event("startup") patterns.
    """
    # --- STARTUP ---
    logger.info("🚀 Starting Admin Dashboard Backend...")
    
    # 1. Database Initialization
    try:
        init_db()
        if not db_healthcheck():
            logger.warning("⚠️ Database connected, but health check failed query.")
    except Exception as e:
        logger.critical(f"🔥 specific database initialization failure: {e}")
        # In strict production, you might want to raise e here to stop deployment
    
    logger.info("✅ System Ready.")
    
    yield  # Application runs here
    
    # --- SHUTDOWN ---
    logger.info("🛑 Shutting down Admin Dashboard Backend...")
    # Close connection pools or HTTP clients here if necessary


# ==============================================================================
# 3. FASTAPI APP INITIALIZATION
# ==============================================================================
app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="Production-grade Admin API for Telegram Digital Store.",
    lifespan=lifespan,
    # Hide docs in production for security
    docs_url="/docs" if settings.ENV != "production" else None,
    redoc_url="/redoc" if settings.ENV != "production" else None,
    openapi_url="/openapi.json" if settings.ENV != "production" else None,
)


# ==============================================================================
# 4. MIDDLEWARE STACK
# ==============================================================================

# A. Performance Timing Middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Adds X-Process-Time header to track latency."""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = f"{process_time:.4f}s"
    return response

# B. GZip Compression (Optimization for large JSON payloads)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# C. CORS (Cross-Origin Resource Sharing)
app.add_middleware(
    CORSMiddleware,
    # In production, replace ["*"] with specific frontend domains from settings
    allow_origins=settings.BACKEND_CORS_ORIGINS if hasattr(settings, "BACKEND_CORS_ORIGINS") else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================================================================
# 5. GLOBAL EXCEPTION HANDLERS
# ==============================================================================

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Returns a clean JSON response for HTTP errors."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "path": request.url.path},
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Overrides default 422 response to provide cleaner validation details."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation Error", 
            "errors": exc.errors(), 
            "body": exc.body
        },
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch-all for unhandled 500 errors. 
    Prevents server stack traces from leaking to the client.
    """
    logger.error(f"Global Exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal Server Error. Please contact support."},
    )


# ==============================================================================
# 6. ROUTING
# ==============================================================================

# Mount the aggregated router from web_routes.py
# The web_routes router already has prefix="/v1", so this mounts at /api/v1
app.include_router(api_v1_router, prefix="/api")


# ==============================================================================
# 7. SYSTEM ENDPOINTS
# ==============================================================================

@app.get("/", tags=["System"], include_in_schema=False)
async def root():
    """Redirect root to docs or return simple status."""
    if settings.ENV != "production":
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/docs")
    return {"message": "Admin Dashboard API is running."}

@app.get("/health", tags=["System"])
async def health_check():
    """
    Kubernetes/Docker health probe endpoint.
    Checks DB connectivity.
    """
    db_status = db_healthcheck()
    status_code = status.HTTP_200_OK if db_status else status.HTTP_503_SERVICE_UNAVAILABLE
    
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "ok" if db_status else "error",
            "service": "admin_dashboard",
            "database": "connected" if db_status else "disconnected",
            "environment": settings.ENV,
            "version": app.version
        }
    )

# ==============================================================================
# ENTRY POINT (For Debugging)
# ==============================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)