"""WebSocket endpoint handlers."""

import asyncio
import json
import secrets
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.api.routes.analysis import analysis_jobs, update_analysis_job
from app.api.websocket.manager import ConnectionManager, ProgressEmitter, manager
from app.config import settings
from app.models.responses import (
    AnalysisStatus,
    WebSocketEvent,
    WebSocketEventType,
)
from app.services.file_manager import file_manager
from app.services.document_parser import document_parser
from app.services.ai_analyzer import ai_analyzer

router = APIRouter()


@router.websocket("/ws/analysis/{session_id}")
async def analysis_websocket(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint for analysis progress streaming.

    Connect to receive real-time updates during compliance analysis.
    Send {"action": "start", "analysis_id": "..."} to begin analysis.
    """
    # Validate session_id
    if not all(c.isalnum() or c == "-" for c in session_id):
        await websocket.close(code=4000, reason="Invalid session ID")
        return

    await manager.connect(websocket, session_id)

    try:
        # Send connection confirmation
        await manager.send_to_connection(
            websocket,
            WebSocketEvent(
                event_type=WebSocketEventType.CONNECTION_STATUS,
                message="Connected to analysis stream",
                data={"session_id": session_id},
            ),
        )

        while True:
            # Wait for messages from client
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
                action = message.get("action")

                if action == "start":
                    analysis_id = message.get("analysis_id")
                    if analysis_id and analysis_id in analysis_jobs:
                        # Run analysis in background
                        asyncio.create_task(
                            run_analysis_with_streaming(
                                session_id, analysis_id
                            )
                        )
                    else:
                        await manager.send_to_connection(
                            websocket,
                            WebSocketEvent(
                                event_type=WebSocketEventType.ANALYSIS_ERROR,
                                message="Invalid analysis ID",
                                data={"error": "Analysis not found"},
                            ),
                        )

                elif action == "ping":
                    await manager.send_to_connection(
                        websocket,
                        WebSocketEvent(
                            event_type=WebSocketEventType.CONNECTION_STATUS,
                            message="pong",
                        ),
                    )

            except json.JSONDecodeError:
                await manager.send_to_connection(
                    websocket,
                    WebSocketEvent(
                        event_type=WebSocketEventType.ANALYSIS_ERROR,
                        message="Invalid message format",
                    ),
                )

    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(websocket)


@router.websocket("/ws/chat/{session_id}")
async def chat_websocket(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint for streaming chat responses.

    Send {"message": "your question"} to chat with the AI assistant.
    Responses are streamed as CHAT_RESPONSE_CHUNK events.
    """
    # Validate session_id
    if not all(c.isalnum() or c == "-" for c in session_id):
        await websocket.close(code=4000, reason="Invalid session ID")
        return

    await manager.connect(websocket, session_id)

    try:
        await manager.send_to_connection(
            websocket,
            WebSocketEvent(
                event_type=WebSocketEventType.CONNECTION_STATUS,
                message="Connected to chat stream",
                data={"session_id": session_id},
            ),
        )

        while True:
            data = await websocket.receive_text()

            try:
                message = json.loads(data)
                user_message = message.get("message", "").strip()

                if not user_message:
                    continue

                # Send typing indicator
                await manager.send_to_connection(
                    websocket,
                    WebSocketEvent(
                        event_type=WebSocketEventType.CHAT_TYPING,
                        message="Assistant is typing...",
                        data={"is_typing": True},
                    ),
                )

                # Stream response
                await stream_chat_response(
                    websocket, session_id, user_message
                )

            except json.JSONDecodeError:
                await manager.send_to_connection(
                    websocket,
                    WebSocketEvent(
                        event_type=WebSocketEventType.CHAT_RESPONSE_COMPLETE,
                        message="Invalid message format",
                        data={"error": "Could not parse message"},
                    ),
                )

    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(websocket)


def is_soc2_document(filename: str) -> bool:
    """Check if a file appears to be a SOC2 Type 2 report."""
    name_lower = filename.lower()
    soc2_indicators = ["soc2", "soc 2", "soc-2", "type 2", "type2", "typeii", "type ii"]
    return any(indicator in name_lower for indicator in soc2_indicators)


def deduplicate_findings(
    all_findings: list[dict],
    document_count: int,
    soc2_document_count: int
) -> list[dict]:
    """
    Deduplicate findings and prioritize those consistent across documents.

    Rules:
    - Findings from SOC2 Type 2 reports get 2x weight
    - Only include findings that appear in multiple documents OR are from SOC2
    - Merge similar findings (same title/category) into one
    """
    # Group findings by a normalized key (title + category)
    finding_groups: dict[str, dict] = {}

    for finding in all_findings:
        # Create a normalized key for grouping
        key = f"{finding.get('title', '').lower().strip()}|{finding.get('category', '').lower().strip()}"

        if key not in finding_groups:
            finding_groups[key] = {
                "finding": finding.copy(),
                "document_count": 0,
                "soc2_count": 0,
                "total_weight": 0,
            }

        group = finding_groups[key]
        group["document_count"] += 1

        # SOC2 findings get double weight
        if finding.get("_from_soc2", False):
            group["soc2_count"] += 1
            group["total_weight"] += 2
        else:
            group["total_weight"] += 1

    # Filter and sort findings
    deduplicated = []
    min_threshold = max(1, document_count // 2)  # Require at least half of documents

    for key, group in finding_groups.items():
        # Include if:
        # 1. Found in SOC2 documents (high trust), OR
        # 2. Found in multiple documents (consistent finding)
        if group["soc2_count"] > 0 or group["document_count"] >= min_threshold:
            finding = group["finding"]
            # Remove internal tracking field
            finding.pop("_from_soc2", None)
            finding.pop("_source_doc", None)
            deduplicated.append({
                **finding,
                "_weight": group["total_weight"],
                "_doc_count": group["document_count"],
            })

    # Sort by weight (higher = more important), then by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    deduplicated.sort(
        key=lambda f: (
            -f.get("_weight", 0),
            severity_order.get(f.get("severity", "").lower(), 4)
        )
    )

    # Remove internal fields from final output
    for finding in deduplicated:
        finding.pop("_weight", None)
        finding.pop("_doc_count", None)

    return deduplicated


def consolidate_framework_coverage(framework_results: list[dict]) -> list[dict]:
    """Consolidate framework coverage from multiple documents."""
    # Group by framework name
    framework_groups: dict[str, list[dict]] = {}

    for fw in framework_results:
        name = fw.get("framework", "")
        if name not in framework_groups:
            framework_groups[name] = []
        framework_groups[name].append(fw)

    # Average the results for each framework
    consolidated = []
    for name, results in framework_groups.items():
        count = len(results)
        consolidated.append({
            "framework": name,
            "coverage_percentage": sum(r.get("coverage_percentage", 0) for r in results) / count,
            "implemented_controls": sum(r.get("implemented_controls", 0) for r in results) // count,
            "partial_controls": sum(r.get("partial_controls", 0) for r in results) // count,
            "missing_controls": sum(r.get("missing_controls", 0) for r in results) // count,
            "total_controls": results[0].get("total_controls", 50),
        })

    return consolidated


async def run_analysis_with_streaming(
    session_id: str, analysis_id: str
) -> None:
    """Run compliance analysis with real-time progress streaming."""
    job = analysis_jobs.get(analysis_id)
    if not job:
        return

    emitter = ProgressEmitter(manager, session_id, total_steps=100)

    try:
        update_analysis_job(analysis_id, status=AnalysisStatus.PROCESSING)

        await emitter.emit(
            WebSocketEventType.ANALYSIS_STARTED,
            "Starting compliance analysis...",
            progress_override=0,
        )

        # Get uploaded files
        files = await file_manager.get_session_files(session_id)
        if not files:
            raise ValueError("No files to analyze")

        total_files = len(files)
        frameworks = job["frameworks"]

        # Track SOC2 documents for weighting
        soc2_documents = [f for f in files if is_soc2_document(f.original_name)]
        soc2_count = len(soc2_documents)

        await emitter.emit(
            WebSocketEventType.DOCUMENT_LOADING,
            f"Analyzing {total_files} document(s), {soc2_count} SOC2 report(s) detected",
            data={"total_files": total_files, "soc2_count": soc2_count},
            progress_override=2,
        )

        # Each file contributes 70% of progress, risk assessment 20%, summary 10%
        file_progress_share = 70 / total_files

        # Collect all findings and framework results
        all_findings: list[dict] = []
        all_framework_results: list[dict] = []

        # Track all strengths from documents
        all_strengths: list[dict] = []

        for i, uploaded_file in enumerate(files):
            is_soc2 = is_soc2_document(uploaded_file.original_name)
            doc_type = "SOC2 Type 2 Report" if is_soc2 else "Document"

            # Document loading
            await emitter.emit(
                WebSocketEventType.DOCUMENT_LOADING,
                f"Loading {uploaded_file.original_name}...",
                data={
                    "filename": uploaded_file.original_name,
                    "is_soc2": is_soc2,
                    "doc_type": doc_type,
                },
                progress_override=5 + i * file_progress_share,
            )

            # Parse the document to extract text
            file_path = await file_manager.get_file_path(session_id, uploaded_file.id)
            if not file_path:
                await emitter.emit(
                    WebSocketEventType.ANALYSIS_ERROR,
                    f"Could not find file: {uploaded_file.original_name}",
                    data={"filename": uploaded_file.original_name},
                )
                continue

            parse_result = await document_parser.parse_file(file_path, uploaded_file.mime_type)

            if parse_result.get("error"):
                await emitter.emit(
                    WebSocketEventType.ANALYSIS_ERROR,
                    f"Error parsing {uploaded_file.original_name}: {parse_result['error']}",
                    data={"filename": uploaded_file.original_name, "error": parse_result["error"]},
                )
                continue

            document_text = parse_result.get("text", "")
            if not document_text.strip():
                await emitter.emit(
                    WebSocketEventType.DOCUMENT_LOADED,
                    f"Warning: No text extracted from {uploaded_file.original_name}",
                    data={"filename": uploaded_file.original_name, "warning": "No text content"},
                )
                continue

            await emitter.emit(
                WebSocketEventType.DOCUMENT_LOADED,
                f"Loaded {doc_type}: {uploaded_file.original_name} ({len(document_text):,} characters)",
                data={
                    "filename": uploaded_file.original_name,
                    "size_bytes": uploaded_file.size_bytes,
                    "text_length": len(document_text),
                    "is_soc2": is_soc2,
                    "truncated": parse_result.get("truncated", False),
                },
            )

            # Analyze document with AI
            await emitter.emit(
                WebSocketEventType.DOCUMENT_ANALYZING,
                f"AI analyzing {uploaded_file.original_name} against {len(frameworks)} framework(s)...",
                data={"filename": uploaded_file.original_name},
            )

            # Call the AI analyzer
            ai_result = await ai_analyzer.analyze_document(
                document_text=document_text,
                filename=uploaded_file.original_name,
                frameworks=frameworks,
                is_soc2=is_soc2,
            )

            if not ai_result.get("success"):
                await emitter.emit(
                    WebSocketEventType.ANALYSIS_ERROR,
                    f"AI analysis failed for {uploaded_file.original_name}: {ai_result.get('error', 'Unknown error')}",
                    data={"filename": uploaded_file.original_name, "error": ai_result.get("error")},
                )
                # Continue with other documents
                continue

            # Process framework coverage from AI
            for fw in frameworks:
                fw_coverage = ai_result.get("framework_coverage", {}).get(fw, {})
                if isinstance(fw_coverage, dict):
                    coverage_pct = fw_coverage.get("coverage_percentage", 70)
                    implemented = fw_coverage.get("implemented_controls", [])
                    partial = fw_coverage.get("partial_controls", [])
                    missing = fw_coverage.get("missing_controls", [])
                else:
                    coverage_pct = 70
                    implemented, partial, missing = [], [], []

                all_framework_results.append({
                    "framework": fw,
                    "coverage_percentage": coverage_pct,
                    "implemented_controls": len(implemented) if isinstance(implemented, list) else implemented,
                    "partial_controls": len(partial) if isinstance(partial, list) else partial,
                    "missing_controls": len(missing) if isinstance(missing, list) else missing,
                    "total_controls": (len(implemented) if isinstance(implemented, list) else 0) +
                                     (len(partial) if isinstance(partial, list) else 0) +
                                     (len(missing) if isinstance(missing, list) else 0) or 50,
                    "_source_doc": uploaded_file.original_name,
                    "_is_soc2": is_soc2,
                })

                await emitter.emit(
                    WebSocketEventType.FRAMEWORK_COMPLETE,
                    f"{fw} analysis complete for {uploaded_file.original_name}: {coverage_pct}%",
                    data={"framework": fw, "coverage": coverage_pct},
                )

            # Process findings from AI
            doc_findings = ai_result.get("findings", [])
            for finding in doc_findings:
                # Add tracking fields
                finding["_from_soc2"] = is_soc2
                finding["_source_doc"] = uploaded_file.original_name

                await emitter.emit(
                    WebSocketEventType.FINDING_DISCOVERED,
                    f"Found: {finding.get('title', 'Unknown')}",
                    data={"finding": {k: v for k, v in finding.items() if not k.startswith("_")}},
                )
                all_findings.append(finding)

            # Process strengths from AI
            doc_strengths = ai_result.get("strengths", [])
            for strength in doc_strengths:
                strength["_from_soc2"] = is_soc2
                strength["_source_doc"] = uploaded_file.original_name
                all_strengths.append(strength)

            if doc_strengths:
                await emitter.emit(
                    WebSocketEventType.DOCUMENT_ANALYZING,
                    f"Identified {len(doc_strengths)} strength(s) in {uploaded_file.original_name}",
                    data={"strengths_count": len(doc_strengths)},
                )

            update_analysis_job(
                analysis_id,
                progress=5 + (i + 1) * file_progress_share,
                current_step=f"Analyzed {uploaded_file.original_name}",
            )

        # Consolidate and deduplicate
        await emitter.emit(
            WebSocketEventType.DOCUMENT_ANALYZING,
            "Consolidating findings across all documents...",
            progress_override=75,
        )
        await asyncio.sleep(0.5)

        # Deduplicate findings with SOC2 weighting
        deduplicated_findings = deduplicate_findings(all_findings, total_files, soc2_count)

        # Consolidate framework coverage
        consolidated_frameworks = consolidate_framework_coverage(all_framework_results)

        results = {
            "overall_compliance_score": 0,
            "frameworks": consolidated_frameworks,
            "findings": deduplicated_findings,
            "risk_assessment": None,
            "executive_summary": None,
        }

        await emitter.emit(
            WebSocketEventType.FINDING_DISCOVERED,
            f"Consolidated {len(all_findings)} findings into {len(deduplicated_findings)} unique findings",
            data={"original_count": len(all_findings), "final_count": len(deduplicated_findings)},
            progress_override=78,
        )

        # Risk assessment
        await emitter.emit(
            WebSocketEventType.RISK_ASSESSMENT_STARTED,
            "Calculating risk assessment...",
            progress_override=80,
        )

        await asyncio.sleep(1.5)

        # Calculate risk scores based on findings
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
        total_risk_points = sum(
            severity_weights.get(f.get("severity", "").lower(), 0)
            for f in deduplicated_findings
        )
        max_risk = len(deduplicated_findings) * 10  # If all were critical

        inherent_score = min(100, 40 + total_risk_points)

        # Residual risk reduced by compliance score
        avg_coverage = (
            sum(fw["coverage_percentage"] for fw in consolidated_frameworks) / len(consolidated_frameworks)
            if consolidated_frameworks else 50
        )
        residual_score = inherent_score * (1 - (avg_coverage / 150))  # Coverage reduces risk
        risk_reduction = ((inherent_score - residual_score) / inherent_score * 100) if inherent_score > 0 else 0

        results["risk_assessment"] = {
            "inherent_risk_level": "Critical" if inherent_score >= 80 else "High" if inherent_score >= 60 else "Medium" if inherent_score >= 40 else "Low",
            "inherent_risk_score": round(inherent_score, 1),
            "residual_risk_level": "Critical" if residual_score >= 80 else "High" if residual_score >= 60 else "Medium" if residual_score >= 40 else "Low",
            "residual_risk_score": round(residual_score, 1),
            "risk_reduction_percentage": round(risk_reduction, 1),
        }

        await emitter.emit(
            WebSocketEventType.RISK_ASSESSMENT_COMPLETE,
            "Risk assessment complete",
            data=results["risk_assessment"],
            progress_override=90,
        )

        # Executive summary - use AI to generate
        await emitter.emit(
            WebSocketEventType.EXECUTIVE_SUMMARY_GENERATING,
            "Generating executive summary with AI...",
            progress_override=92,
        )

        # Prepare framework coverage dict for summary generation
        framework_coverage_dict = {}
        for fw in consolidated_frameworks:
            framework_coverage_dict[fw["framework"]] = {
                "coverage_percentage": fw["coverage_percentage"],
                "implemented_controls": fw["implemented_controls"],
                "partial_controls": fw["partial_controls"],
                "missing_controls": fw["missing_controls"],
            }

        # Generate AI-powered executive summary
        results["executive_summary"] = await ai_analyzer.generate_consolidated_summary(
            all_findings=deduplicated_findings,
            all_strengths=all_strengths,
            framework_coverage=framework_coverage_dict,
            document_count=total_files,
            soc2_count=soc2_count,
        )

        # Calculate overall score
        if results["frameworks"]:
            results["overall_compliance_score"] = sum(
                fw["coverage_percentage"] for fw in results["frameworks"]
            ) / len(results["frameworks"])

        # Complete
        update_analysis_job(
            analysis_id,
            status=AnalysisStatus.COMPLETED,
            progress=100,
            current_step="Complete",
            results=results,
        )

        await emitter.emit(
            WebSocketEventType.ANALYSIS_COMPLETE,
            "Analysis complete!",
            data={
                "analysis_id": analysis_id,
                "overall_score": results["overall_compliance_score"],
                "findings_count": len(results["findings"]),
            },
            progress_override=100,
        )

    except Exception as e:
        update_analysis_job(
            analysis_id,
            status=AnalysisStatus.FAILED,
            error=str(e),
        )

        await emitter.emit(
            WebSocketEventType.ANALYSIS_ERROR,
            f"Analysis failed: {str(e)}",
            data={"error": str(e)},
        )


async def stream_chat_response(
    websocket: WebSocket,
    session_id: str,
    user_message: str,
) -> None:
    """Stream chat response chunks via WebSocket."""
    try:
        import json as json_lib

        import boto3
        from botocore.config import Config

        config = Config(
            connect_timeout=10,
            read_timeout=settings.bedrock_timeout,
        )

        bedrock = boto3.client(
            "bedrock-runtime",
            region_name=settings.aws_region,
            config=config,
        )

        # Build system prompt
        system_prompt = """You are a security compliance expert assistant.
        Help users understand compliance analysis results and provide actionable guidance.
        Be concise and professional."""

        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": settings.bedrock_max_tokens,
            "temperature": settings.bedrock_temperature,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}],
        }

        # Use streaming API
        response = bedrock.invoke_model_with_response_stream(
            modelId=settings.bedrock_model_id,
            body=json_lib.dumps(request_body),
            contentType="application/json",
            accept="application/json",
        )

        full_response = ""
        for event in response.get("body", []):
            chunk = json_lib.loads(event.get("chunk", {}).get("bytes", b"{}"))

            if chunk.get("type") == "content_block_delta":
                text = chunk.get("delta", {}).get("text", "")
                if text:
                    full_response += text
                    await manager.send_to_connection(
                        websocket,
                        WebSocketEvent(
                            event_type=WebSocketEventType.CHAT_RESPONSE_CHUNK,
                            message=text,
                            data={"chunk": text},
                        ),
                    )

        await manager.send_to_connection(
            websocket,
            WebSocketEvent(
                event_type=WebSocketEventType.CHAT_RESPONSE_COMPLETE,
                message="Response complete",
                data={"full_response": full_response},
            ),
        )

    except Exception as e:
        await manager.send_to_connection(
            websocket,
            WebSocketEvent(
                event_type=WebSocketEventType.CHAT_RESPONSE_COMPLETE,
                message=f"Error: {str(e)}",
                data={"error": str(e)},
            ),
        )
