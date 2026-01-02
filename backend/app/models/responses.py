"""API response models."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class UploadedFile(BaseModel):
    """Represents an uploaded file."""

    id: str
    original_name: str
    size_bytes: int
    mime_type: str
    uploaded_at: datetime


class UploadResponse(BaseModel):
    """Response after file upload."""

    success: bool
    file: Optional[UploadedFile] = None
    error: Optional[str] = None


class FileListResponse(BaseModel):
    """Response with list of uploaded files."""

    session_id: str
    files: list[UploadedFile]
    total_size_bytes: int


class AnalysisStatus(str, Enum):
    """Analysis job status."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class AnalysisStartResponse(BaseModel):
    """Response after starting analysis."""

    analysis_id: str
    session_id: str
    status: AnalysisStatus
    message: str


class AnalysisStatusResponse(BaseModel):
    """Response with analysis status."""

    analysis_id: str
    status: AnalysisStatus
    progress_percentage: float
    current_step: Optional[str] = None
    error: Optional[str] = None


class Finding(BaseModel):
    """A compliance finding."""

    severity: str
    category: str
    title: str
    description: str
    recommendation: str
    affected_controls: list[str] = Field(default_factory=list)


class FrameworkCoverage(BaseModel):
    """Coverage for a compliance framework."""

    framework: str
    coverage_percentage: float
    implemented_controls: int
    partial_controls: int
    missing_controls: int
    total_controls: int


class Strength(BaseModel):
    """A vendor security strength."""

    category: str
    title: str
    description: str
    control_references: list[str] = Field(default_factory=list)
    evidence: str = ""


class RiskAssessment(BaseModel):
    """Risk assessment summary with inherent/residual risk model."""

    # Inherent Risk (before controls) - 0-100, higher = more risk
    inherent_risk_score: float
    inherent_risk_level: str  # Critical, High, Medium, Low

    # Control Effectiveness - percentage reduction
    control_effectiveness_score: float  # 0-100%
    control_effectiveness_level: str  # Strong, Adequate, Developing, Weak

    # Residual Risk (after controls) - 0-100, lower = better
    residual_risk_score: float
    residual_risk_level: str  # Critical, High, Medium, Low

    # Legacy fields for backward compatibility
    security_posture_score: float
    security_posture_level: str
    overall_risk_score: float
    overall_risk_level: str

    # Overall recommendation
    recommendation: str = ""  # APPROVED, CONDITIONAL, NOT RECOMMENDED
    recommendation_details: str = ""


class AnalysisResultsResponse(BaseModel):
    """Full analysis results."""

    analysis_id: str
    status: AnalysisStatus
    overall_compliance_score: float
    frameworks: list[FrameworkCoverage]
    findings: list[Finding]
    strengths: list[Strength] = Field(default_factory=list)
    risk_assessment: Optional[RiskAssessment] = None
    executive_summary: Optional[str] = None
    completed_at: Optional[datetime] = None


class ConnectionTestResponse(BaseModel):
    """Response from connection test."""

    success: bool
    region: str
    model_id: str
    message: str
    latency_ms: Optional[float] = None
    error: Optional[str] = None


class ChatMessageResponse(BaseModel):
    """Response with chat message."""

    message_id: str
    role: str
    content: str
    timestamp: datetime


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str
    detail: Optional[str] = None
    code: Optional[str] = None


class WebSocketEventType(str, Enum):
    """WebSocket event types."""

    # Analysis progress events
    ANALYSIS_STARTED = "analysis_started"
    DOCUMENT_LOADING = "document_loading"
    DOCUMENT_LOADED = "document_loaded"
    DOCUMENT_ANALYZING = "document_analyzing"
    FINDING_DISCOVERED = "finding_discovered"
    FRAMEWORK_COMPLETE = "framework_complete"
    RISK_ASSESSMENT_STARTED = "risk_assessment_started"
    RISK_ASSESSMENT_COMPLETE = "risk_assessment_complete"
    EXECUTIVE_SUMMARY_GENERATING = "executive_summary_generating"
    ANALYSIS_COMPLETE = "analysis_complete"
    ANALYSIS_ERROR = "analysis_error"

    # Chat events
    CHAT_MESSAGE = "chat_message"
    CHAT_TYPING = "chat_typing"
    CHAT_RESPONSE_CHUNK = "chat_response_chunk"
    CHAT_RESPONSE_COMPLETE = "chat_response_complete"

    # Connection events
    CONNECTION_STATUS = "connection_status"


class WebSocketEvent(BaseModel):
    """WebSocket event payload."""

    event_type: WebSocketEventType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    data: dict[str, Any] = Field(default_factory=dict)
    progress_percentage: Optional[float] = None
    message: Optional[str] = None
