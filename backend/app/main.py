"""
Main FastAPI Application Entrypoint.
Initializes database schema, mounts API routers, configures CORS,
and coordinates GNN Behavioral Detection Services.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pathlib import Path

from backend.app.core.config import settings
from backend.app.database.session import engine, Base
from backend.app.database import models
from backend.app.api import health, traces, inference, graphs, models_api, cicd, reports

# Ensure database tables exist
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Ransomware Behavior Detection via Graph Neural Networks (API Call Graphs) for CI/CD Supply Chain Security",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration
# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://ransomware-gnn-frontend.onrender.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(health.router, prefix="/api")
app.include_router(traces.router, prefix="/api")
app.include_router(inference.router, prefix="/api")
app.include_router(graphs.router, prefix="/api")
app.include_router(models_api.router, prefix="/api")
app.include_router(cicd.router, prefix="/api")
app.include_router(reports.router, prefix="/api")

# Mount Static Frontend Distribution if built
frontend_dist = settings.BASE_DIR / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        file_path = frontend_dist / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(frontend_dist / "index.html")
else:
    @app.get("/")
    def root():
        return {
            "project": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "docs_url": "/docs",
            "status": "operational"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
