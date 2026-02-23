"""FastAPI application entry point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import init_db
from app.api import scans, hosts, vulnerabilities, websocket

# Initialize FastAPI app
app = FastAPI(
    title="CrushGear Web Dashboard API",
    description="REST API for CrushGear penetration testing automation",
    version="1.0.0"
)

# CORS middleware for localhost development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Vite default dev server
        "http://localhost:3000",  # Alternative React dev server
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(scans.router, prefix="/api", tags=["scans"])
app.include_router(hosts.router, prefix="/api", tags=["hosts"])
app.include_router(vulnerabilities.router, prefix="/api", tags=["vulnerabilities"])
app.include_router(websocket.router, prefix="/ws", tags=["websocket"])


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    init_db()
    print("✓ Database initialized")


@app.get("/")
async def root():
    """Root endpoint - API health check."""
    return {
        "message": "CrushGear Web Dashboard API",
        "status": "running",
        "version": "1.0.0"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}
