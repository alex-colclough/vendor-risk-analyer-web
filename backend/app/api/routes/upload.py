"""File upload endpoints with security validation."""

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile

from app.rate_limiter import limiter
from app.models.responses import (
    ErrorResponse,
    FileListResponse,
    UploadResponse,
)
from app.services.file_manager import FileManager, FileValidationError

router = APIRouter()
file_manager = FileManager()


@router.post(
    "/upload",
    response_model=UploadResponse,
    responses={400: {"model": ErrorResponse}, 413: {"model": ErrorResponse}},
)
@limiter.limit("20/minute")  # 20 uploads per minute per IP
async def upload_file(
    request: Request,
    session_id: str = Form(..., min_length=1, max_length=64),
    file: UploadFile = File(...),
):
    """
    Upload a document for analysis.

    Supports: PDF, DOCX, XLSX, XLS, CSV, TXT, MD
    Max file size: 100MB
    Max total per session: 500MB
    """
    # Validate session_id format
    if not all(c.isalnum() or c == "-" for c in session_id):
        raise HTTPException(
            status_code=400,
            detail="Session ID must be alphanumeric with hyphens only",
        )

    try:
        uploaded_file = await file_manager.save_upload(session_id, file)
        return UploadResponse(success=True, file=uploaded_file)
    except FileValidationError as e:
        return UploadResponse(success=False, error=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Upload failed")


@router.get(
    "/upload/{session_id}",
    response_model=FileListResponse,
)
async def list_files(session_id: str):
    """List all uploaded files for a session."""
    # Validate session_id format
    if not all(c.isalnum() or c == "-" for c in session_id):
        raise HTTPException(
            status_code=400,
            detail="Session ID must be alphanumeric with hyphens only",
        )

    files = await file_manager.get_session_files(session_id)
    total_size = sum(f.size_bytes for f in files)

    return FileListResponse(
        session_id=session_id,
        files=files,
        total_size_bytes=total_size,
    )


@router.delete(
    "/upload/{session_id}/{file_id}",
    response_model=UploadResponse,
)
async def delete_file(session_id: str, file_id: str):
    """Delete an uploaded file."""
    # Validate inputs
    if not all(c.isalnum() or c == "-" for c in session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID")
    if not all(c.isalnum() or c in "-_" for c in file_id):
        raise HTTPException(status_code=400, detail="Invalid file ID")

    deleted = await file_manager.delete_file(session_id, file_id)
    if deleted:
        return UploadResponse(success=True)
    else:
        return UploadResponse(success=False, error="File not found")


@router.delete(
    "/upload/{session_id}",
    response_model=UploadResponse,
)
async def cleanup_session(session_id: str):
    """Delete all files for a session."""
    if not all(c.isalnum() or c == "-" for c in session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID")

    await file_manager.cleanup_session(session_id)
    return UploadResponse(success=True)
