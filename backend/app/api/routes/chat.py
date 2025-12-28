"""Chat endpoints for AI assistant."""

import logging
import re
import secrets
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Request

from app.api.routes.analysis import analysis_jobs
from app.config import settings
from app.rate_limiter import limiter
from app.models.requests import ChatRequest
from app.models.responses import ChatMessageResponse, ErrorResponse

router = APIRouter()
logger = logging.getLogger(__name__)

# In-memory chat history (use Redis in production)
chat_histories: dict[str, list[dict]] = {}

# Maximum message length
MAX_MESSAGE_LENGTH = 4000


def sanitize_chat_message(message: str) -> str:
    """
    Sanitize user chat message to prevent prompt injection attacks.

    This function:
    1. Limits message length
    2. Removes potential prompt injection patterns
    3. Normalizes whitespace
    """
    if not message:
        return ""

    # Limit length
    message = message[:MAX_MESSAGE_LENGTH]

    # Remove potential prompt injection patterns (case-insensitive)
    dangerous_patterns = [
        r"ignore\s+(all\s+)?previous\s+instructions?",
        r"disregard\s+(all\s+)?previous",
        r"forget\s+(all\s+)?previous",
        r"you\s+are\s+now\s+a",
        r"act\s+as\s+if\s+you\s+are",
        r"pretend\s+(you\s+are|to\s+be)",
        r"system\s*:\s*",
        r"assistant\s*:\s*",
        r"human\s*:\s*",
        r"<\|.*?\|>",  # Special tokens
        r"\[INST\]|\[/INST\]",  # Instruction markers
        r"<<SYS>>|<</SYS>>",  # System markers
    ]

    for pattern in dangerous_patterns:
        message = re.sub(pattern, "[filtered]", message, flags=re.IGNORECASE)

    # Normalize whitespace
    message = " ".join(message.split())

    return message.strip()


@router.post(
    "/chat",
    response_model=ChatMessageResponse,
    responses={400: {"model": ErrorResponse}},
)
@limiter.limit("30/minute")  # 30 messages per minute per IP
async def send_chat_message(request: Request, chat_request: ChatRequest):
    """
    Send a chat message to the AI assistant.

    The assistant can answer questions about compliance analysis,
    explain findings, and provide recommendations.

    For streaming responses, use the WebSocket endpoint
    /ws/chat/{session_id} instead.
    """
    # Sanitize user message
    sanitized_message = sanitize_chat_message(chat_request.message)

    if not sanitized_message or len(sanitized_message) < 2:
        raise HTTPException(status_code=400, detail="Message too short or invalid")

    # Initialize chat history for session if needed
    if chat_request.session_id not in chat_histories:
        chat_histories[chat_request.session_id] = []

    # Add user message to history (using sanitized version)
    user_message = {
        "role": "user",
        "content": sanitized_message,
        "timestamp": datetime.utcnow(),
    }
    chat_histories[chat_request.session_id].append(user_message)

    try:
        # Build context from analysis results if available and requested
        context = ""
        if chat_request.include_context:
            context = await build_analysis_context(chat_request.session_id)

        # Generate response using Bedrock
        response_content = await generate_chat_response(
            chat_request.session_id,
            sanitized_message,  # Use sanitized message
            context,
            chat_histories[chat_request.session_id],
        )

        # Add assistant message to history
        assistant_message = {
            "role": "assistant",
            "content": response_content,
            "timestamp": datetime.utcnow(),
        }
        chat_histories[chat_request.session_id].append(assistant_message)

        return ChatMessageResponse(
            message_id=secrets.token_urlsafe(8),
            role="assistant",
            content=response_content,
            timestamp=datetime.utcnow(),
        )

    except Exception as e:
        # Log error details server-side, return generic message to client
        logger.error(f"Chat error for session {chat_request.session_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to generate response. Please try again.",
        )


async def build_analysis_context(session_id: str) -> str:
    """Build context string from analysis results."""
    # Find analysis for this session
    for analysis_id, job in analysis_jobs.items():
        if job.get("session_id") == session_id and job.get("results"):
            results = job["results"]
            context_parts = [
                "Analysis Results Summary:",
                f"- Overall Compliance Score: {results.get('overall_compliance_score', 0):.1f}%",
            ]

            # Add framework coverage
            for fw in results.get("frameworks", []):
                context_parts.append(
                    f"- {fw.get('framework')}: {fw.get('coverage_percentage', 0):.1f}% coverage"
                )

            # Add finding summary
            findings = results.get("findings", [])
            if findings:
                severity_counts = {}
                for f in findings:
                    sev = f.get("severity", "unknown")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1

                context_parts.append(
                    f"- Findings: {', '.join(f'{count} {sev}' for sev, count in severity_counts.items())}"
                )

            # Add executive summary if available
            if results.get("executive_summary"):
                context_parts.append(f"\nExecutive Summary:\n{results['executive_summary']}")

            return "\n".join(context_parts)

    return ""


async def generate_chat_response(
    session_id: str,
    user_message: str,
    context: str,
    history: list[dict],
) -> str:
    """Generate chat response using AWS Bedrock."""
    import json

    import boto3
    from botocore.config import Config

    config = Config(
        connect_timeout=10,
        read_timeout=settings.bedrock_timeout,
        retries={"max_attempts": 2},
    )

    bedrock = boto3.client(
        "bedrock-runtime",
        region_name=settings.aws_region,
        config=config,
    )

    # Build system prompt
    system_prompt = """You are a security compliance expert assistant helping users understand their vendor security analysis results.

Your role is to:
1. Explain compliance findings in clear, actionable terms
2. Answer questions about security frameworks (SOC2, ISO27001, NIST CSF, HIPAA, GDPR, PCI-DSS)
3. Provide recommendations for addressing compliance gaps
4. Help prioritize remediation efforts based on risk

Be concise, professional, and focus on practical guidance. If you don't have specific analysis results to reference, provide general best-practice advice.

"""
    if context:
        system_prompt += f"\nCurrent Analysis Context:\n{context}"

    # Build messages from history (last 10 messages for context)
    messages = []
    for msg in history[-10:]:
        messages.append({
            "role": msg["role"],
            "content": msg["content"],
        })

    request_body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": settings.bedrock_max_tokens,
        "temperature": settings.bedrock_temperature,
        "system": system_prompt,
        "messages": messages,
    }

    response = bedrock.invoke_model(
        modelId=settings.bedrock_model_id,
        body=json.dumps(request_body),
        contentType="application/json",
        accept="application/json",
    )

    response_body = json.loads(response["body"].read())
    return response_body["content"][0]["text"]


@router.get("/chat/{session_id}/history")
async def get_chat_history(session_id: str, limit: int = 50):
    """Get chat history for a session."""
    if not all(c.isalnum() or c == "-" for c in session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID")

    history = chat_histories.get(session_id, [])
    return {
        "session_id": session_id,
        "messages": [
            {
                "role": msg["role"],
                "content": msg["content"],
                "timestamp": msg["timestamp"].isoformat(),
            }
            for msg in history[-limit:]
        ],
    }


@router.delete("/chat/{session_id}/history")
async def clear_chat_history(session_id: str):
    """Clear chat history for a session."""
    if not all(c.isalnum() or c == "-" for c in session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID")

    if session_id in chat_histories:
        del chat_histories[session_id]

    return {"success": True}
