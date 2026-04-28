from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from datetime import datetime
from typing import List, Optional


app = FastAPI(
    title="Security Resilience Platform API",
    version="0.1.0",
    description="Backend API for authorised cyber security resilience assessments."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://security-resilience-platform.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    asset_id: str
    target_url: str
    testing_level: str
    frameworks: List[str]
    authorised: bool
    authorisation_ref: str


class ScanResponse(BaseModel):
    job_id: str
    status: str
    message: str
    created_at: str


@app.get("/")
def root():
    return {
        "service": "Security Resilience Platform API",
        "status": "online",
        "version": "0.1.0"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/scan-jobs", response_model=ScanResponse)
def create_scan_job(request: ScanRequest):
    if not request.authorised:
        return ScanResponse(
            job_id="blocked",
            status="blocked",
            message="Scan blocked. Target is not authorised.",
            created_at=datetime.utcnow().isoformat()
        )

    if not request.authorisation_ref.strip():
        return ScanResponse(
            job_id="blocked",
            status="blocked",
            message="Scan blocked. Authorisation reference is required.",
            created_at=datetime.utcnow().isoformat()
        )

    return ScanResponse(
        job_id=f"JOB-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        status="queued",
        message="Authorised scan job accepted. Scanner worker integration comes next.",
        created_at=datetime.utcnow().isoformat()
    )