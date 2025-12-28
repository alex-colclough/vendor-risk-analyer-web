"""Export endpoints for analysis results."""

import json
import re
from datetime import datetime
from html import escape as html_escape

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from app.api.routes.analysis import analysis_jobs
from app.rate_limiter import limiter
from app.models.responses import AnalysisStatus

router = APIRouter()


def escape_html(text: str) -> str:
    """Safely escape HTML to prevent XSS in PDF generation."""
    if not text:
        return ""
    return html_escape(str(text), quote=True)


def sanitize_filename(name: str) -> str:
    """Sanitize a string for use in a filename."""
    if not name:
        return ""
    # Replace spaces with underscores, remove unsafe characters
    sanitized = re.sub(r'[^\w\s-]', '', name)
    sanitized = re.sub(r'[\s]+', '_', sanitized)
    return sanitized[:50]  # Limit length


@router.get("/export/json/{analysis_id}")
@limiter.limit("30/minute")  # 30 exports per minute per IP
async def export_json(request: Request, analysis_id: str):
    """
    Download analysis results as JSON.

    Returns the full analysis results including compliance scores,
    findings, risk assessment, and executive summary.
    """
    if analysis_id not in analysis_jobs:
        raise HTTPException(status_code=404, detail="Analysis not found")

    job = analysis_jobs[analysis_id]

    if job["status"] != AnalysisStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail="Analysis not completed yet",
        )

    results = job.get("results")
    if not results:
        raise HTTPException(
            status_code=500,
            detail="Results not available",
        )

    # Build export data
    export_data = {
        "analysis_id": analysis_id,
        "session_id": job["session_id"],
        "vendor_name": job.get("vendor_name"),
        "reviewed_by": job.get("reviewed_by"),
        "ticket_number": job.get("ticket_number"),
        "frameworks_analyzed": job["frameworks"],
        "started_at": job["started_at"].isoformat() if job.get("started_at") else None,
        "completed_at": (
            job["completed_at"].isoformat() if job.get("completed_at") else None
        ),
        "results": results,
    }

    # Generate filename with vendor name and date
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    vendor_name = job.get("vendor_name")
    if vendor_name:
        safe_vendor = sanitize_filename(vendor_name)
        filename = f"{safe_vendor}_Security_Assessment_{date_str}.json"
    else:
        filename = f"Security_Assessment_{date_str}.json"

    return Response(
        content=json.dumps(export_data, indent=2, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/export/pdf/{analysis_id}")
@limiter.limit("10/minute")  # 10 PDF exports per minute per IP (expensive operation)
async def export_pdf(request: Request, analysis_id: str):
    """
    Download analysis results as PDF report.

    Generates a formatted PDF report with compliance scores,
    findings table, risk assessment, and executive summary.
    """
    if analysis_id not in analysis_jobs:
        raise HTTPException(status_code=404, detail="Analysis not found")

    job = analysis_jobs[analysis_id]

    if job["status"] != AnalysisStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail="Analysis not completed yet",
        )

    results = job.get("results")
    if not results:
        raise HTTPException(
            status_code=500,
            detail="Results not available",
        )

    try:
        pdf_bytes = await generate_pdf_report(analysis_id, job, results)

        # Generate filename with vendor name and date
        date_str = datetime.utcnow().strftime("%Y-%m-%d")
        vendor_name = job.get("vendor_name")
        if vendor_name:
            safe_vendor = sanitize_filename(vendor_name)
            filename = f"{safe_vendor}_Security_Assessment_{date_str}.pdf"
        else:
            filename = f"Security_Assessment_{date_str}.pdf"

        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Content-Type-Options": "nosniff",
            },
        )
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="PDF generation not available. Install weasyprint.",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"PDF generation failed: {str(e)}",
        )


async def generate_pdf_report(
    analysis_id: str, job: dict, results: dict
) -> bytes:
    """Generate PDF report from analysis results with XSS protection."""
    from weasyprint import HTML

    # Escape all user-controlled data to prevent XSS in PDF
    safe_vendor_name = escape_html(job.get("vendor_name", ""))
    safe_reviewed_by = escape_html(job.get("reviewed_by", ""))
    safe_ticket_number = escape_html(job.get("ticket_number", ""))
    safe_frameworks = [escape_html(fw) for fw in job.get("frameworks", [])]
    safe_executive_summary = escape_html(results.get("executive_summary", "No summary available."))

    # Escape finding data
    findings = results.get("findings", [])
    safe_findings = []
    for f in findings:
        safe_findings.append({
            "severity": escape_html(f.get("severity", "")),
            "category": escape_html(f.get("category", "")),
            "title": escape_html(f.get("title", "Untitled Finding")),
            "description": escape_html(f.get("description", "No description provided.")),
            "root_cause": escape_html(f.get("root_cause", "")),
            "business_impact": escape_html(f.get("business_impact", "")),
            "control_references": [escape_html(ref) for ref in f.get("control_references", [])] if isinstance(f.get("control_references"), list) else escape_html(f.get("control_references", "")),
            "evidence": escape_html(f.get("evidence", "No specific evidence cited.")),
            "recommendation": escape_html(f.get("recommendation", "No recommendation provided.")),
            "remediation_effort": escape_html(f.get("remediation_effort", "")),
            "remediation_timeline": escape_html(f.get("remediation_timeline", "To be determined")),
            "finding_id": escape_html(f.get("finding_id", "")),
        })

    # Escape framework data
    frameworks = results.get("frameworks", [])
    safe_framework_data = []
    for fw in frameworks:
        safe_framework_data.append({
            "framework": escape_html(fw.get("framework", "")),
            "coverage_percentage": fw.get("coverage_percentage", 0),
            "implemented_controls": fw.get("implemented_controls", 0),
            "partial_controls": fw.get("partial_controls", 0),
            "missing_controls": fw.get("missing_controls", 0),
        })

    # Get risk assessment data
    risk = results.get("risk_assessment", {})
    security_posture_score = risk.get("security_posture_score", 0)
    security_posture_level = escape_html(risk.get("security_posture_level", "N/A"))
    overall_risk_score = risk.get("overall_risk_score", 0)
    overall_risk_level = escape_html(risk.get("overall_risk_level", "N/A"))

    # Count findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Build HTML report with professional styling
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Vendor Security Assessment Report</title>
        <style>
            @page {{
                size: letter;
                margin: 0.75in;
                @top-right {{
                    content: "CONFIDENTIAL";
                    font-size: 9px;
                    color: #999;
                }}
                @bottom-center {{
                    content: "Page " counter(page) " of " counter(pages);
                    font-size: 9px;
                    color: #666;
                }}
            }}
            body {{
                font-family: 'Helvetica Neue', Arial, sans-serif;
                font-size: 10pt;
                line-height: 1.5;
                color: #2d3748;
            }}
            .cover-page {{
                text-align: center;
                padding-top: 2in;
                page-break-after: always;
            }}
            .cover-title {{
                font-size: 28pt;
                font-weight: bold;
                color: #1a365d;
                margin-bottom: 0.5in;
            }}
            .cover-subtitle {{
                font-size: 14pt;
                color: #4a5568;
                margin-bottom: 1in;
            }}
            .cover-meta {{
                font-size: 11pt;
                color: #718096;
                margin-top: 2in;
            }}
            .cover-meta p {{
                margin: 5px 0;
            }}
            h1 {{
                font-size: 18pt;
                color: #1a365d;
                border-bottom: 2px solid #3182ce;
                padding-bottom: 8px;
                margin-top: 30px;
                margin-bottom: 15px;
            }}
            h2 {{
                font-size: 14pt;
                color: #2c5282;
                margin-top: 25px;
                margin-bottom: 10px;
            }}
            h3 {{
                font-size: 12pt;
                color: #2d3748;
                margin-top: 20px;
                margin-bottom: 8px;
            }}
            .section {{
                margin-bottom: 25px;
            }}
            .score-container {{
                display: flex;
                justify-content: space-between;
                margin: 20px 0;
            }}
            .score-box {{
                text-align: center;
                padding: 20px;
                border-radius: 8px;
                width: 30%;
                box-sizing: border-box;
            }}
            .score-box.primary {{
                background: linear-gradient(135deg, #1a365d 0%, #2c5282 100%);
                color: white;
            }}
            .score-box.inherent {{
                background: #fed7d7;
                border: 2px solid #fc8181;
            }}
            .score-box.residual {{
                background: #fefcbf;
                border: 2px solid #f6e05e;
            }}
            .score-value {{
                font-size: 36pt;
                font-weight: bold;
                margin: 10px 0;
            }}
            .score-label {{
                font-size: 10pt;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
            .score-sublabel {{
                font-size: 9pt;
                opacity: 0.8;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 15px 0;
                font-size: 9pt;
            }}
            th {{
                background: #2d3748;
                color: white;
                padding: 10px 12px;
                text-align: left;
                font-weight: 600;
            }}
            td {{
                padding: 10px 12px;
                border-bottom: 1px solid #e2e8f0;
            }}
            tr:nth-child(even) {{
                background: #f7fafc;
            }}
            .severity-badge {{
                display: inline-block;
                padding: 3px 10px;
                border-radius: 12px;
                font-size: 8pt;
                font-weight: 600;
                text-transform: uppercase;
            }}
            .severity-critical {{
                background: #c53030;
                color: white;
            }}
            .severity-high {{
                background: #dd6b20;
                color: white;
            }}
            .severity-medium {{
                background: #d69e2e;
                color: white;
            }}
            .severity-low {{
                background: #38a169;
                color: white;
            }}
            .executive-summary {{
                background: #f7fafc;
                padding: 20px;
                border-left: 4px solid #3182ce;
                margin: 20px 0;
                font-size: 10pt;
            }}
            .findings-summary {{
                display: flex;
                justify-content: space-around;
                margin: 20px 0;
                padding: 15px;
                background: #f7fafc;
                border-radius: 8px;
            }}
            .finding-count {{
                text-align: center;
            }}
            .finding-count .count {{
                font-size: 24pt;
                font-weight: bold;
            }}
            .finding-count .label {{
                font-size: 9pt;
                text-transform: uppercase;
            }}
            .finding-count.critical .count {{ color: #c53030; }}
            .finding-count.high .count {{ color: #dd6b20; }}
            .finding-count.medium .count {{ color: #d69e2e; }}
            .finding-count.low .count {{ color: #38a169; }}
            .risk-matrix {{
                margin: 20px 0;
            }}
            .framework-bar {{
                background: #e2e8f0;
                height: 24px;
                border-radius: 4px;
                margin: 8px 0;
                position: relative;
            }}
            .framework-bar-fill {{
                height: 100%;
                border-radius: 4px;
                background: linear-gradient(90deg, #3182ce 0%, #2c5282 100%);
            }}
            .framework-bar-label {{
                position: absolute;
                right: 10px;
                top: 3px;
                font-size: 9pt;
                font-weight: 600;
                color: #2d3748;
            }}
            .footer {{
                margin-top: 40px;
                padding-top: 20px;
                border-top: 2px solid #e2e8f0;
                font-size: 9pt;
                color: #718096;
            }}
            .disclaimer {{
                background: #fffaf0;
                border: 1px solid #ed8936;
                padding: 15px;
                border-radius: 4px;
                margin: 20px 0;
                font-size: 9pt;
            }}
            .page-break {{
                page-break-before: always;
            }}
        </style>
    </head>
    <body>
        <!-- Cover Page -->
        <div class="cover-page">
            <div class="cover-title">Vendor Security<br>Assessment Report</div>
            <div class="cover-subtitle">{f'<strong>{safe_vendor_name}</strong><br>' if safe_vendor_name else ''}Third-Party Risk Analysis &amp; Compliance Review</div>
            <div class="cover-meta">
                {f'<p><strong>Vendor:</strong> {safe_vendor_name}</p>' if safe_vendor_name else ''}
                <p><strong>Report ID:</strong> {analysis_id[:16].upper()}</p>
                <p><strong>Assessment Date:</strong> {datetime.utcnow().strftime("%B %d, %Y")}</p>
                <p><strong>Frameworks Evaluated:</strong> {", ".join(safe_frameworks)}</p>
                <p><strong>Classification:</strong> CONFIDENTIAL</p>
            </div>
        </div>

        <!-- Executive Summary -->
        <h1>1. Executive Summary</h1>
        <div class="section">
            <div class="executive-summary">
                {safe_executive_summary}
            </div>

            <div class="score-container">
                <div class="score-box primary">
                    <div class="score-label">Overall Compliance</div>
                    <div class="score-value">{results.get("overall_compliance_score", 0):.0f}%</div>
                    <div class="score-sublabel">Framework Coverage</div>
                </div>
                <div class="score-box" style="background: {'#c6f6d5' if security_posture_score >= 80 else '#fefcbf' if security_posture_score >= 60 else '#fed7d7'}; border: 2px solid {'#38a169' if security_posture_score >= 80 else '#d69e2e' if security_posture_score >= 60 else '#c53030'};">
                    <div class="score-label">Security Posture</div>
                    <div class="score-value" style="color: {'#38a169' if security_posture_score >= 80 else '#d69e2e' if security_posture_score >= 60 else '#c53030'};">{security_posture_score:.0f}</div>
                    <div class="score-sublabel">{security_posture_level}</div>
                </div>
                <div class="score-box" style="background: {'#c6f6d5' if overall_risk_score < 25 else '#fefcbf' if overall_risk_score < 50 else '#fed7d7'}; border: 2px solid {'#38a169' if overall_risk_score < 25 else '#d69e2e' if overall_risk_score < 50 else '#c53030'};">
                    <div class="score-label">Overall Risk</div>
                    <div class="score-value" style="color: {'#38a169' if overall_risk_score < 25 else '#d69e2e' if overall_risk_score < 50 else '#c53030'};">{overall_risk_score:.0f}</div>
                    <div class="score-sublabel">{overall_risk_level}</div>
                </div>
            </div>
        </div>

        <!-- Findings Overview -->
        <h1>2. Findings Overview</h1>
        <div class="section">
            <div class="findings-summary">
                <div class="finding-count critical">
                    <div class="count">{severity_counts["critical"]}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="finding-count high">
                    <div class="count">{severity_counts["high"]}</div>
                    <div class="label">High</div>
                </div>
                <div class="finding-count medium">
                    <div class="count">{severity_counts["medium"]}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="finding-count low">
                    <div class="count">{severity_counts["low"]}</div>
                    <div class="label">Low</div>
                </div>
            </div>
        </div>

        <!-- Detailed Findings -->
        <h1 class="page-break">3. Detailed Findings</h1>
        {"".join(f'''
        <div class="section" style="margin-bottom: 20px; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; page-break-inside: avoid;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <span class="severity-badge severity-{f.get("severity", "").lower()}">{f.get("severity", "").upper()}</span>
                <span style="font-size: 9pt; color: #718096;">{f.get("finding_id") or f"F-{i+1:03d}"}</span>
            </div>
            <h3 style="margin: 0 0 10px 0; color: #1a365d;">{f.get("title", "Untitled Finding")}</h3>
            <table style="width: 100%; font-size: 9pt; margin: 0;">
                <tr>
                    <td style="width: 120px; font-weight: 600; vertical-align: top; padding: 5px 10px 5px 0; border: none;">Category:</td>
                    <td style="padding: 5px 0; border: none;">{f.get("category", "").replace("_", " ").title()}</td>
                </tr>
                <tr>
                    <td style="font-weight: 600; vertical-align: top; padding: 5px 10px 5px 0; border: none;">Description:</td>
                    <td style="padding: 5px 0; border: none;">{f.get("description", "No description provided.")}</td>
                </tr>
                {f'<tr><td style="font-weight: 600; vertical-align: top; padding: 5px 10px 5px 0; border: none;">Root Cause:</td><td style="padding: 5px 0; border: none;">{f.get("root_cause")}</td></tr>' if f.get("root_cause") else ""}
                {f'<tr><td style="font-weight: 600; vertical-align: top; padding: 5px 10px 5px 0; border: none;">Business Impact:</td><td style="padding: 5px 0; border: none; color: #c53030;">{f.get("business_impact")}</td></tr>' if f.get("business_impact") else ""}
                {f'<tr><td style="font-weight: 600; vertical-align: top; padding: 5px 10px 5px 0; border: none;">Control References:</td><td style="padding: 5px 0; border: none; font-family: monospace; font-size: 8pt;">{", ".join(f.get("control_references")) if isinstance(f.get("control_references"), list) else f.get("control_references", "")}</td></tr>' if f.get("control_references") else ""}
                <tr>
                    <td style="font-weight: 600; vertical-align: top; padding: 5px 10px 5px 0; border: none;">Evidence:</td>
                    <td style="padding: 5px 0; border: none; font-style: italic; color: #4a5568;">"{f.get("evidence", "No specific evidence cited.")}"</td>
                </tr>
                <tr style="background: #f7fafc;">
                    <td style="font-weight: 600; vertical-align: top; padding: 8px 10px 8px 0; border: none;">Recommendation:</td>
                    <td style="padding: 8px 0; border: none; color: #2c5282;">{f.get("recommendation", "No recommendation provided.")}</td>
                </tr>
                {f'<tr><td style="font-weight: 600; vertical-align: top; padding: 5px 10px 5px 0; border: none;">Remediation Effort:</td><td style="padding: 5px 0; border: none;"><span style="background: #{"fed7d7" if f.get("remediation_effort") == "high" else "#fefcbf" if f.get("remediation_effort") == "medium" else "#c6f6d5"}; padding: 2px 8px; border-radius: 4px; font-size: 8pt;">{f.get("remediation_effort", "").upper()}</span> &nbsp; <span style="color: #718096;">Timeline: {f.get("remediation_timeline", "To be determined")}</span></td></tr>' if f.get("remediation_effort") else ""}
            </table>
        </div>
        ''' for i, f in enumerate(safe_findings))}

        <!-- Framework Coverage -->
        <h1 class="page-break">4. Framework Coverage Analysis</h1>
        <div class="section">
            <table>
                <thead>
                    <tr>
                        <th>Framework</th>
                        <th style="width: 100px;">Coverage</th>
                        <th style="width: 80px;">Implemented</th>
                        <th style="width: 80px;">Partial</th>
                        <th style="width: 80px;">Missing</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f'''
                    <tr>
                        <td><strong>{fw.get("framework", "")}</strong></td>
                        <td>
                            <div class="framework-bar">
                                <div class="framework-bar-fill" style="width: {fw.get("coverage_percentage", 0)}%;"></div>
                                <span class="framework-bar-label">{fw.get("coverage_percentage", 0):.0f}%</span>
                            </div>
                        </td>
                        <td style="text-align: center; color: #38a169; font-weight: 600;">{fw.get("implemented_controls", 0)}</td>
                        <td style="text-align: center; color: #d69e2e; font-weight: 600;">{fw.get("partial_controls", 0)}</td>
                        <td style="text-align: center; color: #c53030; font-weight: 600;">{fw.get("missing_controls", 0)}</td>
                    </tr>
                    ''' for fw in safe_framework_data)}
                </tbody>
            </table>
        </div>

        {"" if not results.get("risk_assessment") else f'''
        <!-- Risk Assessment -->
        <h1>5. Risk Assessment</h1>
        <div class="section">
            <table>
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Score</th>
                        <th>Rating</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>Security Posture</strong></td>
                        <td style="text-align: center; font-weight: 600;">{security_posture_score:.0f}/100</td>
                        <td><span class="severity-badge severity-{"low" if security_posture_score >= 80 else "medium" if security_posture_score >= 60 else "high"}">{security_posture_level}</span></td>
                        <td>Overall security control maturity based on framework coverage (higher is better)</td>
                    </tr>
                    <tr>
                        <td><strong>Overall Risk</strong></td>
                        <td style="text-align: center; font-weight: 600;">{overall_risk_score:.0f}/100</td>
                        <td><span class="severity-badge severity-{"low" if overall_risk_score < 25 else "medium" if overall_risk_score < 50 else "high" if overall_risk_score < 75 else "critical"}">{overall_risk_level}</span></td>
                        <td>Aggregate risk score based on findings severity (lower is better)</td>
                    </tr>
                </tbody>
            </table>

            <div style="margin-top: 20px; padding: 15px; background: #f7fafc; border-radius: 8px;">
                <h3 style="margin: 0 0 10px 0; font-size: 11pt;">Score Interpretation</h3>
                <table style="font-size: 9pt;">
                    <tr>
                        <td style="padding: 5px 15px 5px 0; border: none;"><strong>Security Posture:</strong></td>
                        <td style="padding: 5px; border: none;">80-100 = Strong | 60-79 = Moderate | 40-59 = Developing | 0-39 = Weak</td>
                    </tr>
                    <tr>
                        <td style="padding: 5px 15px 5px 0; border: none;"><strong>Overall Risk:</strong></td>
                        <td style="padding: 5px; border: none;">0-24 = Low | 25-49 = Medium | 50-74 = High | 75-100 = Critical</td>
                    </tr>
                </table>
            </div>
        </div>
        '''}

        <!-- Signature Block -->
        <h1 class="page-break">6. Assessment Sign-Off</h1>
        <div class="section">
            <table style="width: 100%; border: 2px solid #2d3748; border-radius: 8px;">
                <tbody>
                    <tr>
                        <td style="width: 30%; padding: 15px; background: #f7fafc; font-weight: 600; border-bottom: 1px solid #e2e8f0;">Vendor Assessed:</td>
                        <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; font-size: 12pt;">{safe_vendor_name or "Not specified"}</td>
                    </tr>
                    <tr>
                        <td style="padding: 15px; background: #f7fafc; font-weight: 600; border-bottom: 1px solid #e2e8f0;">Reviewed By:</td>
                        <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; font-size: 12pt;">{safe_reviewed_by or "Not specified"}</td>
                    </tr>
                    <tr>
                        <td style="padding: 15px; background: #f7fafc; font-weight: 600; border-bottom: 1px solid #e2e8f0;">Ticket/Request Number:</td>
                        <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; font-size: 12pt;">{safe_ticket_number or "Not specified"}</td>
                    </tr>
                    <tr>
                        <td style="padding: 15px; background: #f7fafc; font-weight: 600; border-bottom: 1px solid #e2e8f0;">Assessment Date:</td>
                        <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; font-size: 12pt;">{datetime.utcnow().strftime("%B %d, %Y")}</td>
                    </tr>
                    <tr>
                        <td style="padding: 15px; background: #f7fafc; font-weight: 600; border-bottom: 1px solid #e2e8f0;">Report ID:</td>
                        <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; font-family: monospace;">{analysis_id[:16].upper()}</td>
                    </tr>
                    <tr>
                        <td style="padding: 15px; background: #f7fafc; font-weight: 600;">Frameworks Evaluated:</td>
                        <td style="padding: 15px;">{", ".join(safe_frameworks)}</td>
                    </tr>
                </tbody>
            </table>

            <div style="margin-top: 30px; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
                <p style="margin-bottom: 15px; font-weight: 600;">Reviewer Acknowledgment:</p>
                <p style="color: #4a5568; font-size: 9pt; line-height: 1.6;">
                    I have reviewed the vendor documentation and findings contained in this report. The assessment was conducted
                    in accordance with the organization's third-party risk management policies and procedures. The findings and
                    recommendations represent my professional opinion based on the information available at the time of review.
                </p>
                <div style="margin-top: 25px; display: flex; justify-content: space-between;">
                    <div style="width: 45%;">
                        <div style="border-bottom: 1px solid #2d3748; height: 40px;"></div>
                        <p style="margin-top: 5px; font-size: 9pt; color: #718096;">Signature</p>
                    </div>
                    <div style="width: 30%;">
                        <div style="border-bottom: 1px solid #2d3748; height: 40px;"></div>
                        <p style="margin-top: 5px; font-size: 9pt; color: #718096;">Date</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Assessment Methodology -->
        <h1 class="page-break">7. Assessment Methodology</h1>
        <div class="section">
            <h3>Scope and Approach</h3>
            <p>This third-party risk assessment was conducted using a risk-based methodology aligned with industry best practices including NIST, ISO 27001, and SOC 2 Trust Services Criteria. The assessment evaluated the vendor's security controls based on documentation provided.</p>

            <h3>Assessment Procedures</h3>
            <ul style="margin: 10px 0; padding-left: 20px;">
                <li>Document review and analysis of security policies, procedures, and audit reports</li>
                <li>Control mapping against applicable compliance frameworks</li>
                <li>Gap analysis comparing documented controls against framework requirements</li>
                <li>Risk rating based on control effectiveness and potential business impact</li>
                <li>Deduplication and correlation of findings across multiple documents</li>
            </ul>

            <h3>Severity Classification</h3>
            <table style="margin: 15px 0;">
                <thead>
                    <tr>
                        <th style="width: 100px;">Severity</th>
                        <th>Definition</th>
                        <th style="width: 150px;">Expected Resolution</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="severity-badge severity-critical">CRITICAL</span></td>
                        <td>Fundamental security control missing or ineffective; immediate exploitation risk; regulatory violation likely</td>
                        <td>Immediate (0-30 days)</td>
                    </tr>
                    <tr>
                        <td><span class="severity-badge severity-high">HIGH</span></td>
                        <td>Material weakness in control design or operation; significant risk exposure requiring urgent remediation</td>
                        <td>30-60 days</td>
                    </tr>
                    <tr>
                        <td><span class="severity-badge severity-medium">MEDIUM</span></td>
                        <td>Significant deficiency that should be addressed; control partially effective or inconsistently applied</td>
                        <td>60-90 days</td>
                    </tr>
                    <tr>
                        <td><span class="severity-badge severity-low">LOW</span></td>
                        <td>Opportunity for improvement; best practice recommendation; minor gap with limited risk exposure</td>
                        <td>90+ days</td>
                    </tr>
                </tbody>
            </table>

            <h3>Limitations</h3>
            <ul style="margin: 10px 0; padding-left: 20px; color: #718096;">
                <li>This assessment is based solely on documentation provided and does not include technical testing or on-site verification</li>
                <li>Findings represent a point-in-time evaluation and may not reflect the current state of controls</li>
                <li>The assessment does not guarantee the absence of security vulnerabilities or compliance gaps not evident in the documentation</li>
                <li>Control effectiveness was assessed based on documented evidence; actual operational effectiveness may vary</li>
            </ul>
        </div>

        <!-- Disclaimer -->
        <div class="disclaimer">
            <strong>Disclaimer:</strong> This assessment is based on the documentation provided and represents a point-in-time evaluation.
            Findings should be validated with the vendor and reassessed periodically. This report does not constitute legal advice
            or guarantee compliance with any regulatory framework. The assessor makes no warranties regarding the accuracy or completeness
            of vendor-provided documentation.
        </div>

        <!-- Footer -->
        <div class="footer">
            <p><strong>Generated by:</strong> Vendor Security Analyzer (AI-Powered Third-Party Risk Assessment)</p>
            <p><strong>Report Generated:</strong> {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
            <p><strong>Vendor:</strong> {safe_vendor_name or "Not specified"} | <strong>Reviewed by:</strong> {safe_reviewed_by or "Not specified"} | <strong>Ticket:</strong> {safe_ticket_number or "N/A"}</p>
            <p><strong>Assessment Frameworks:</strong> {", ".join(safe_frameworks)}</p>
            <p style="margin-top: 10px;">This document contains confidential information intended solely for the authorized recipient(s).
            Unauthorized distribution, copying, or disclosure is strictly prohibited.</p>
        </div>
    </body>
    </html>
    """

    # Generate PDF
    html = HTML(string=html_content)
    return html.write_pdf()
