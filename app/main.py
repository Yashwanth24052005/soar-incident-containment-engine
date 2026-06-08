"""
SOAR Incident Containment Engine - Week 1
FastAPI listener: Webhook ingestion and data normalization
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import logging

from app.routers import alerts
from app.models.alert import NormalizedAlert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("soar.main")

app = FastAPI(
    title="SOAR Incident Containment Engine",
    description="Ingests SIEM webhook alerts, normalizes them, and prepares for automated response.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts.router, prefix="/api/v1", tags=["Alerts"])


@app.get("/")
def health_check():
    return {"status": "SOAR engine running", "version": "1.0.0"}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
