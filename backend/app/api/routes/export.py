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
    """
    Generate PDF report from analysis results with XSS protection.

    Format follows enterprise vendor security assessment standards with:
    - Executive Summary with Key Assessment Results
    - Inherent/Residual Risk Model
    - Security Control Analysis
    - Key Findings (Strengths and Concerns)
    - Recommendations
    - Risk Scoring Summary
    """
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

    # Escape strengths data
    strengths = results.get("strengths", [])
    safe_strengths = []
    for s in strengths:
        safe_strengths.append({
            "category": escape_html(s.get("category", "")),
            "title": escape_html(s.get("title", "")),
            "description": escape_html(s.get("description", "")),
            "control_references": [escape_html(ref) for ref in s.get("control_references", [])] if isinstance(s.get("control_references"), list) else [],
            "evidence": escape_html(s.get("evidence", "")),
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

    # Get risk assessment data (with new Okta-style fields)
    risk = results.get("risk_assessment", {})

    # New inherent/residual risk fields
    inherent_risk_score = risk.get("inherent_risk_score", 50)
    inherent_risk_level = escape_html(risk.get("inherent_risk_level", "Medium"))
    control_effectiveness_score = risk.get("control_effectiveness_score", 70)
    control_effectiveness_level = escape_html(risk.get("control_effectiveness_level", "Adequate"))
    residual_risk_score = risk.get("residual_risk_score", 15)
    residual_risk_level = escape_html(risk.get("residual_risk_level", "Low"))
    risk_reduction = risk.get("risk_reduction_percentage", 70)
    recommendation = escape_html(risk.get("recommendation", "APPROVED"))
    recommendation_details = escape_html(risk.get("recommendation_details", ""))

    # Legacy fields for backward compatibility
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

    # Determine recommendation badge color
    rec_colors = {
        "APPROVED": ("#38a169", "#c6f6d5"),
        "APPROVED WITH CONDITIONS": ("#d69e2e", "#fefcbf"),
        "CONDITIONAL": ("#dd6b20", "#fed7d7"),
        "NOT RECOMMENDED": ("#c53030", "#fed7d7"),
    }
    rec_text_color, rec_bg_color = rec_colors.get(recommendation, ("#718096", "#f7fafc"))

    # Build HTML report with Okta-style professional formatting
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Vendor Security Assessment Report</title>
        <style>
            @page {{
                size: letter;
                margin: 0.6in 0.7in;
                @top-right {{
                    content: "CONFIDENTIAL";
                    font-size: 8px;
                    color: #999;
                }}
                @bottom-center {{
                    content: "Page " counter(page);
                    font-size: 8px;
                    color: #666;
                }}
            }}
            body {{
                font-family: 'Times New Roman', Georgia, serif;
                font-size: 10pt;
                line-height: 1.4;
                color: #1a1a1a;
            }}
            h1 {{
                font-size: 14pt;
                font-weight: bold;
                text-transform: uppercase;
                margin-top: 20px;
                margin-bottom: 12px;
                border-bottom: 1px solid #000;
                padding-bottom: 4px;
            }}
            h2 {{
                font-size: 11pt;
                font-weight: bold;
                margin-top: 15px;
                margin-bottom: 8px;
            }}
            h3 {{
                font-size: 10pt;
                font-weight: bold;
                margin-top: 12px;
                margin-bottom: 6px;
            }}
            .title-block {{
                text-align: center;
                margin-bottom: 20px;
            }}
            .title-main {{
                font-size: 16pt;
                font-weight: bold;
                text-transform: uppercase;
                margin-bottom: 15px;
            }}
            .title-meta {{
                font-size: 9pt;
                margin-bottom: 3px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 10px 0;
                font-size: 9pt;
            }}
            th {{
                background: #f5f5f5;
                border: 1px solid #ccc;
                padding: 6px 8px;
                text-align: left;
                font-weight: bold;
            }}
            td {{
                border: 1px solid #ccc;
                padding: 6px 8px;
                vertical-align: top;
            }}
            .no-border td, .no-border th {{
                border: none;
            }}
            .key-results-table td {{
                padding: 8px 12px;
            }}
            .recommendation-box {{
                background: {rec_bg_color};
                border: 2px solid {rec_text_color};
                padding: 12px 15px;
                margin: 15px 0;
                border-radius: 4px;
            }}
            .recommendation-title {{
                font-weight: bold;
                color: {rec_text_color};
                font-size: 11pt;
                margin-bottom: 5px;
            }}
            .summary-box {{
                background: #f9f9f9;
                border-left: 3px solid #333;
                padding: 12px 15px;
                margin: 12px 0;
            }}
            .severity-badge {{
                display: inline-block;
                padding: 2px 8px;
                border-radius: 3px;
                font-size: 8pt;
                font-weight: bold;
                text-transform: uppercase;
            }}
            .severity-critical {{ background: #c53030; color: white; }}
            .severity-high {{ background: #dd6b20; color: white; }}
            .severity-medium {{ background: #d69e2e; color: white; }}
            .severity-low {{ background: #38a169; color: white; }}
            .strength-item {{
                margin-bottom: 8px;
                padding-left: 15px;
            }}
            .finding-item {{
                margin-bottom: 10px;
                padding: 8px;
                background: #fafafa;
                border: 1px solid #eee;
            }}
            .page-break {{
                page-break-before: always;
            }}
            ul {{
                margin: 5px 0;
                padding-left: 20px;
            }}
            li {{
                margin-bottom: 3px;
            }}
            .risk-score {{
                font-size: 18pt;
                font-weight: bold;
            }}
            .footer-section {{
                margin-top: 20px;
                padding-top: 10px;
                border-top: 1px solid #ccc;
                font-size: 8pt;
                color: #666;
            }}
        </style>
    </head>
    <body>
        <!-- Title Block -->
        <div class="title-block">
            <div class="title-main">{safe_vendor_name.upper() if safe_vendor_name else 'VENDOR'} SECURITY ASSESSMENT REPORT</div>
            <div class="title-meta"><strong>Assessment Date:</strong> {datetime.utcnow().strftime("%B %d, %Y")} &nbsp;&nbsp;
                <strong>Vendor:</strong> {safe_vendor_name or "Not specified"} &nbsp;&nbsp;
                <strong>Report Version:</strong> 1.0</div>
            <div class="title-meta"><strong>Service Category:</strong> {", ".join(safe_frameworks)} &nbsp;&nbsp;
                <strong>Assessor:</strong> {safe_reviewed_by or "Security & Compliance Team"}</div>
        </div>

        <!-- EXECUTIVE SUMMARY -->
        <h1>Executive Summary</h1>

        <div class="summary-box">
            {safe_executive_summary}
        </div>

        <h2>Key Assessment Results</h2>
        <table class="key-results-table">
            <thead>
                <tr>
                    <th>Metric</th>
                    <th>Score</th>
                    <th>Rating</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>Inherent Risk Score</strong></td>
                    <td>{inherent_risk_score:.0f}/100</td>
                    <td>{inherent_risk_level}</td>
                </tr>
                <tr>
                    <td><strong>Residual Risk Score</strong></td>
                    <td>{residual_risk_score:.0f}/100</td>
                    <td>{residual_risk_level}</td>
                </tr>
                <tr>
                    <td><strong>Control Effectiveness</strong></td>
                    <td>{risk_reduction:.0f}% Reduction</td>
                    <td>{control_effectiveness_level}</td>
                </tr>
                <tr>
                    <td><strong>Overall Risk Rating</strong></td>
                    <td><strong>{residual_risk_level.upper()} RISK</strong></td>
                    <td>{recommendation.replace("_", " ")}</td>
                </tr>
            </tbody>
        </table>

        <h2>Key Findings Summary</h2>
        <p><strong>Strengths:</strong> {f"Identified {len(safe_strengths)} security strengths including " + ", ".join([s.get("title", "") for s in safe_strengths[:3]]) + ("..." if len(safe_strengths) > 3 else "") if safe_strengths else "Limited strengths documented in provided materials."}</p>

        <p><strong>Areas for Attention:</strong> {f"Identified {sum(severity_counts.values())} findings ({severity_counts['critical']} critical, {severity_counts['high']} high, {severity_counts['medium']} medium, {severity_counts['low']} low severity)." if sum(severity_counts.values()) > 0 else "No significant findings identified."}</p>

        <div class="recommendation-box">
            <div class="recommendation-title">Recommendation: {recommendation.replace("_", " ")}</div>
            <div>{recommendation_details}</div>
        </div>

        <!-- INHERENT RISK ASSESSMENT -->
        <h1>1. Inherent Risk Assessment</h1>

        <h2>1.1 Risk Scoring Methodology</h2>
        <p>Inherent risk represents the level of risk before considering the vendor's security controls. Assessment considers data sensitivity, regulatory impact, business criticality, access scope, and threat landscape.</p>

        <h2>1.2 Inherent Risk Factor Analysis</h2>
        <table>
            <thead>
                <tr>
                    <th>Risk Factor</th>
                    <th style="width: 80px;">Score</th>
                    <th>Rationale</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>Data Sensitivity</strong></td>
                    <td>{"16/20" if "HIPAA" in safe_frameworks or "PCI_DSS" in safe_frameworks else "12/20" if "SOC2" in safe_frameworks else "8/20"}</td>
                    <td>{"High - Handles regulated data (healthcare/financial)" if "HIPAA" in safe_frameworks or "PCI_DSS" in safe_frameworks else "Medium-High - Handles business-critical data" if "SOC2" in safe_frameworks else "Medium - Standard business data handling"}</td>
                </tr>
                <tr>
                    <td><strong>Regulatory Impact</strong></td>
                    <td>{"12/20" if "HIPAA" in safe_frameworks or "PCI_DSS" in safe_frameworks or "GDPR" in safe_frameworks else "8/20"}</td>
                    <td>{"High - Subject to regulatory compliance requirements" if "HIPAA" in safe_frameworks or "PCI_DSS" in safe_frameworks or "GDPR" in safe_frameworks else "Medium - Standard compliance obligations"}</td>
                </tr>
                <tr>
                    <td><strong>Business Criticality</strong></td>
                    <td>{"10/20" if "SOC2" in safe_frameworks else "8/20"}</td>
                    <td>{"Medium-High - Service is critical for operations" if "SOC2" in safe_frameworks else "Medium - Standard business service"}</td>
                </tr>
                <tr>
                    <td><strong>Access Scope</strong></td>
                    <td>6/20</td>
                    <td>Medium-Low - API-based integration with limited attack surface</td>
                </tr>
                <tr>
                    <td><strong>Threat Landscape</strong></td>
                    <td>4/20</td>
                    <td>Low - Standard threat profile with mature security ecosystem</td>
                </tr>
            </tbody>
        </table>

        <p><strong>TOTAL INHERENT RISK SCORE: {inherent_risk_score:.0f}/100 ({inherent_risk_level} Risk)</strong></p>

        <!-- SECURITY CONTROL ANALYSIS -->
        <h1 class="page-break">2. Security Control Analysis</h1>

        <h2>2.1 Framework Coverage Overview</h2>
        <table>
            <thead>
                <tr>
                    <th>Framework</th>
                    <th style="width: 80px;">Coverage</th>
                    <th style="width: 80px;">Implemented</th>
                    <th style="width: 80px;">Partial</th>
                    <th style="width: 80px;">Missing</th>
                </tr>
            </thead>
            <tbody>
                {"".join(f'''
                <tr>
                    <td><strong>{fw.get("framework", "")}</strong></td>
                    <td style="text-align: center;">{fw.get("coverage_percentage", 0):.0f}%</td>
                    <td style="text-align: center; color: #38a169;">{fw.get("implemented_controls", 0)}</td>
                    <td style="text-align: center; color: #d69e2e;">{fw.get("partial_controls", 0)}</td>
                    <td style="text-align: center; color: #c53030;">{fw.get("missing_controls", 0)}</td>
                </tr>
                ''' for fw in safe_framework_data)}
            </tbody>
        </table>

        <h2>2.2 Control Maturity Assessment</h2>
        <table>
            <thead>
                <tr>
                    <th>Dimension</th>
                    <th>Assessment</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>Control Effectiveness</strong></td>
                    <td>{control_effectiveness_score:.0f}% - {control_effectiveness_level}</td>
                </tr>
                <tr>
                    <td><strong>Security Posture</strong></td>
                    <td>{security_posture_score:.0f}/100 - {security_posture_level}</td>
                </tr>
                <tr>
                    <td><strong>Overall Compliance</strong></td>
                    <td>{results.get("overall_compliance_score", 0):.0f}% Average Framework Coverage</td>
                </tr>
            </tbody>
        </table>

        <!-- RESIDUAL RISK ASSESSMENT -->
        <h1>3. Residual Risk Assessment</h1>

        <h2>3.1 Risk Calculation</h2>
        <p><strong>Formula:</strong> Residual Risk = Inherent Risk × (1 - Control Effectiveness %)</p>

        <table>
            <thead>
                <tr>
                    <th>Component</th>
                    <th>Value</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>Inherent Risk</strong></td>
                    <td>{inherent_risk_score:.0f}/100</td>
                    <td>Baseline risk before controls ({inherent_risk_level})</td>
                </tr>
                <tr>
                    <td><strong>Control Effectiveness</strong></td>
                    <td>{control_effectiveness_score:.0f}%</td>
                    <td>Risk reduction through implemented controls ({control_effectiveness_level})</td>
                </tr>
                <tr>
                    <td><strong>Residual Risk</strong></td>
                    <td><strong>{residual_risk_score:.0f}/100</strong></td>
                    <td>Remaining risk after controls ({residual_risk_level})</td>
                </tr>
                <tr>
                    <td><strong>Risk Reduction</strong></td>
                    <td>{risk_reduction:.0f}%</td>
                    <td>{"Strong" if risk_reduction >= 70 else "Adequate" if risk_reduction >= 50 else "Developing"} risk mitigation achieved</td>
                </tr>
            </tbody>
        </table>

        <!-- KEY FINDINGS -->
        <h1 class="page-break">4. Key Findings and Observations</h1>

        <h2>4.1 Positive Findings (Strengths)</h2>
        {f'''
        <ul>
        {"".join(f'<li><strong>{s.get("title", "Security Strength")}:</strong> {s.get("description", "")[:200]}{"..." if len(s.get("description", "")) > 200 else ""}</li>' for s in safe_strengths[:5])}
        </ul>
        ''' if safe_strengths else '<p>Limited strengths documented in provided materials.</p>'}

        <h2>4.2 Areas for Attention (Findings)</h2>
        {f'''
        <div class="findings-summary" style="margin: 10px 0; padding: 10px; background: #f5f5f5;">
            <strong>Finding Distribution:</strong>
            <span class="severity-badge severity-critical">{severity_counts["critical"]} Critical</span>
            <span class="severity-badge severity-high">{severity_counts["high"]} High</span>
            <span class="severity-badge severity-medium">{severity_counts["medium"]} Medium</span>
            <span class="severity-badge severity-low">{severity_counts["low"]} Low</span>
        </div>
        ''' if sum(severity_counts.values()) > 0 else ''}

        {"".join(f'''
        <div class="finding-item">
            <strong><span class="severity-badge severity-{f.get("severity", "").lower()}">{f.get("severity", "").upper()}</span>
            {f.get("title", "Untitled Finding")}</strong><br>
            <em>{f.get("category", "").replace("_", " ").title()}</em><br>
            {f.get("description", "")[:300]}{"..." if len(f.get("description", "")) > 300 else ""}<br>
            <strong>Recommendation:</strong> {f.get("recommendation", "")[:200]}{"..." if len(f.get("recommendation", "")) > 200 else ""}
        </div>
        ''' for f in safe_findings[:8])}

        {f'<p><em>... and {len(safe_findings) - 8} additional findings. See detailed findings appendix for complete list.</em></p>' if len(safe_findings) > 8 else ''}

        <!-- RECOMMENDATIONS -->
        <h1>5. Recommendations</h1>

        <h2>5.1 Vendor Engagement Recommendation</h2>
        <div class="recommendation-box">
            <div class="recommendation-title">{recommendation.replace("_", " ")}</div>
            <div>{recommendation_details}</div>
        </div>

        <h2>5.2 Conditions and Monitoring</h2>
        <ul>
            {"<li>Implement complementary user entity controls as documented</li>" if residual_risk_level in ["Low", "Medium"] else "<li>Remediation of critical/high findings required before engagement</li>"}
            <li>Annual reassessment recommended</li>
            <li>{"Standard" if residual_risk_level == "Low" else "Enhanced"} vendor monitoring and periodic review</li>
            {"<li>Request updated SOC 2 Type II report annually</li>" if "SOC2" in safe_frameworks else ""}
        </ul>

        <!-- RISK SCORING SUMMARY -->
        <h1>6. Risk Scoring Summary</h1>

        <table>
            <thead>
                <tr>
                    <th>Assessment Component</th>
                    <th>Score</th>
                    <th>Rating</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>Inherent Risk</strong></td>
                    <td>{inherent_risk_score:.0f}/100</td>
                    <td>{inherent_risk_level}</td>
                </tr>
                <tr>
                    <td><strong>Control Effectiveness</strong></td>
                    <td>{control_effectiveness_score:.0f}%</td>
                    <td>{control_effectiveness_level}</td>
                </tr>
                <tr>
                    <td><strong>Residual Risk</strong></td>
                    <td>{residual_risk_score:.0f}/100</td>
                    <td>{residual_risk_level}</td>
                </tr>
                <tr>
                    <td><strong>Risk Reduction</strong></td>
                    <td>{risk_reduction:.0f}%</td>
                    <td>{"Excellent" if risk_reduction >= 70 else "Good" if risk_reduction >= 50 else "Needs Improvement"}</td>
                </tr>
            </tbody>
        </table>

        <p style="text-align: center; font-size: 12pt; font-weight: bold; margin-top: 20px;">
            FINAL RECOMMENDATION: {recommendation.replace("_", " ")} - {residual_risk_level.upper()} RISK
        </p>

        <!-- CONCLUSION -->
        <h1>7. Conclusion</h1>

        <p>This security assessment evaluated {safe_vendor_name or "the vendor"}'s security posture based on documentation provided against {len(safe_frameworks)} compliance framework(s): {", ".join(safe_frameworks)}.</p>

        <p><strong>Key Conclusions:</strong></p>
        <ul>
            <li>Inherent risk score of {inherent_risk_score:.0f}/100 indicates {inherent_risk_level.lower()} baseline risk</li>
            <li>Control effectiveness of {control_effectiveness_score:.0f}% demonstrates {control_effectiveness_level.lower()} security controls</li>
            <li>Residual risk score of {residual_risk_score:.0f}/100 places vendor in {residual_risk_level.upper()} RISK category</li>
            <li>{f"{len(safe_strengths)} security strengths identified" if safe_strengths else "Limited strengths documented"}</li>
            <li>{f"{sum(severity_counts.values())} findings identified requiring attention" if sum(severity_counts.values()) > 0 else "No significant findings identified"}</li>
        </ul>

        <p><strong>Suitability:</strong> Based on the assessment, {safe_vendor_name or "the vendor"} is {"suitable" if residual_risk_level in ["Low", "Medium"] else "conditionally suitable" if residual_risk_level == "High" else "not recommended"} for engagement {"with standard monitoring" if residual_risk_level == "Low" else "with enhanced monitoring" if residual_risk_level == "Medium" else "pending remediation of identified issues"}.</p>

        <!-- ASSESSMENT SIGN-OFF -->
        <h1 class="page-break">Assessment Sign-Off</h1>

        <table>
            <tbody>
                <tr>
                    <td style="width: 35%; background: #f5f5f5;"><strong>Vendor Assessed:</strong></td>
                    <td>{safe_vendor_name or "Not specified"}</td>
                </tr>
                <tr>
                    <td style="background: #f5f5f5;"><strong>Reviewed By:</strong></td>
                    <td>{safe_reviewed_by or "Not specified"}</td>
                </tr>
                <tr>
                    <td style="background: #f5f5f5;"><strong>Ticket/Request Number:</strong></td>
                    <td>{safe_ticket_number or "Not specified"}</td>
                </tr>
                <tr>
                    <td style="background: #f5f5f5;"><strong>Assessment Date:</strong></td>
                    <td>{datetime.utcnow().strftime("%B %d, %Y")}</td>
                </tr>
                <tr>
                    <td style="background: #f5f5f5;"><strong>Report ID:</strong></td>
                    <td style="font-family: monospace;">{analysis_id[:16].upper()}</td>
                </tr>
                <tr>
                    <td style="background: #f5f5f5;"><strong>Frameworks Evaluated:</strong></td>
                    <td>{", ".join(safe_frameworks)}</td>
                </tr>
                <tr>
                    <td style="background: #f5f5f5;"><strong>Next Review Date:</strong></td>
                    <td>{(datetime.utcnow().replace(year=datetime.utcnow().year + 1)).strftime("%B %Y")} (Annual)</td>
                </tr>
            </tbody>
        </table>

        <div style="margin-top: 30px; padding: 15px; border: 1px solid #ccc;">
            <p><strong>Reviewer Acknowledgment:</strong></p>
            <p style="font-size: 9pt; color: #666;">
                I have reviewed the vendor documentation and findings contained in this report. The assessment was conducted
                in accordance with the organization's third-party risk management policies. The findings and recommendations
                represent professional opinion based on the information available at the time of review.
            </p>
            <div style="margin-top: 20px; display: flex; justify-content: space-between;">
                <div style="width: 45%;">
                    <div style="border-bottom: 1px solid #333; height: 30px;"></div>
                    <p style="font-size: 8pt; color: #666;">Signature</p>
                </div>
                <div style="width: 30%;">
                    <div style="border-bottom: 1px solid #333; height: 30px;"></div>
                    <p style="font-size: 8pt; color: #666;">Date</p>
                </div>
            </div>
        </div>

        <!-- Disclaimer -->
        <div style="margin-top: 20px; padding: 10px; background: #fff9e6; border: 1px solid #e6c200; font-size: 8pt;">
            <strong>Disclaimer:</strong> This assessment is based on documentation provided and represents a point-in-time evaluation.
            Findings should be validated with the vendor and reassessed periodically. This report does not constitute legal advice
            or guarantee compliance with any regulatory framework.
        </div>

        <!-- Footer -->
        <div class="footer-section">
            <p><strong>Report Generated:</strong> {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
            <p>This document contains confidential information intended solely for the authorized recipient(s).
            Unauthorized distribution, copying, or disclosure is strictly prohibited.</p>
        </div>
    </body>
    </html>
    """

    # Generate PDF
    html = HTML(string=html_content)
    return html.write_pdf()
