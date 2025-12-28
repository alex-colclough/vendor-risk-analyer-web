"""Analysis endpoints."""

import asyncio
import secrets
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Request

from app.config import settings
from app.rate_limiter import limiter
from app.models.requests import AnalysisRequest
from app.models.responses import (
    AnalysisResultsResponse,
    AnalysisStartResponse,
    AnalysisStatus,
    AnalysisStatusResponse,
    ErrorResponse,
)
from app.services.file_manager import file_manager

router = APIRouter()

# In-memory storage for analysis jobs (use Redis in production)
analysis_jobs: dict[str, dict] = {}


@router.post(
    "/analysis/start",
    response_model=AnalysisStartResponse,
    responses={400: {"model": ErrorResponse}},
)
@limiter.limit("10/hour")  # 10 analyses per hour per IP
async def start_analysis(request: Request, analysis_request: AnalysisRequest):
    """
    Start compliance analysis on uploaded documents.

    The analysis runs asynchronously. Use the WebSocket endpoint
    /ws/analysis/{session_id} to receive real-time progress updates,
    or poll /analysis/{analysis_id}/status for status.
    """
    # Validate session has files
    files = await file_manager.get_session_files(analysis_request.session_id)
    if not files:
        raise HTTPException(
            status_code=400,
            detail="No files uploaded for this session",
        )

    # Generate analysis ID
    analysis_id = secrets.token_urlsafe(16)

    # Store job info
    analysis_jobs[analysis_id] = {
        "session_id": analysis_request.session_id,
        "frameworks": analysis_request.frameworks,
        "vendor_name": analysis_request.vendor_name,
        "reviewed_by": analysis_request.reviewed_by,
        "ticket_number": analysis_request.ticket_number,
        "status": AnalysisStatus.PENDING,
        "progress": 0,
        "current_step": None,
        "results": None,
        "error": None,
        "started_at": datetime.utcnow(),
        "completed_at": None,
    }

    # Analysis will be started by WebSocket handler when client connects
    # This allows real-time streaming of progress

    return AnalysisStartResponse(
        analysis_id=analysis_id,
        session_id=analysis_request.session_id,
        status=AnalysisStatus.PENDING,
        message=f"Analysis queued. Connect to WebSocket /ws/analysis/{analysis_request.session_id} to start and receive progress updates.",
    )


@router.get(
    "/analysis/{analysis_id}/status",
    response_model=AnalysisStatusResponse,
)
async def get_analysis_status(analysis_id: str):
    """Get the current status of an analysis job."""
    if analysis_id not in analysis_jobs:
        raise HTTPException(status_code=404, detail="Analysis not found")

    job = analysis_jobs[analysis_id]
    return AnalysisStatusResponse(
        analysis_id=analysis_id,
        status=job["status"],
        progress_percentage=job["progress"],
        current_step=job["current_step"],
        error=job["error"],
    )


@router.get(
    "/analysis/{analysis_id}/results",
    response_model=AnalysisResultsResponse,
)
async def get_analysis_results(analysis_id: str):
    """Get the results of a completed analysis."""
    if analysis_id not in analysis_jobs:
        raise HTTPException(status_code=404, detail="Analysis not found")

    job = analysis_jobs[analysis_id]

    if job["status"] == AnalysisStatus.PENDING:
        raise HTTPException(
            status_code=400,
            detail="Analysis has not started yet",
        )

    if job["status"] == AnalysisStatus.PROCESSING:
        raise HTTPException(
            status_code=400,
            detail="Analysis is still in progress",
        )

    if job["status"] == AnalysisStatus.FAILED:
        raise HTTPException(
            status_code=400,
            detail=f"Analysis failed: {job['error']}",
        )

    results = job.get("results")
    if not results:
        raise HTTPException(
            status_code=500,
            detail="Results not available",
        )

    return AnalysisResultsResponse(
        analysis_id=analysis_id,
        status=job["status"],
        overall_compliance_score=results.get("overall_compliance_score", 0),
        frameworks=results.get("frameworks", []),
        findings=results.get("findings", []),
        risk_assessment=results.get("risk_assessment"),
        executive_summary=results.get("executive_summary"),
        completed_at=job.get("completed_at"),
    )


def update_analysis_job(
    analysis_id: str,
    status: Optional[AnalysisStatus] = None,
    progress: Optional[float] = None,
    current_step: Optional[str] = None,
    results: Optional[dict] = None,
    error: Optional[str] = None,
):
    """Update analysis job status (called by analyzer service)."""
    if analysis_id not in analysis_jobs:
        return

    job = analysis_jobs[analysis_id]
    if status is not None:
        job["status"] = status
    if progress is not None:
        job["progress"] = progress
    if current_step is not None:
        job["current_step"] = current_step
    if results is not None:
        job["results"] = results
    if error is not None:
        job["error"] = error
    if status == AnalysisStatus.COMPLETED:
        job["completed_at"] = datetime.utcnow()
