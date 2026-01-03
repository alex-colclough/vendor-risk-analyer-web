"""AI-powered document analysis service using AWS Bedrock."""

import asyncio
import json
import random
from typing import Optional

import boto3
import httpx
from botocore.config import Config
from botocore.exceptions import ClientError

from app.config import settings


class AIAnalyzer:
    """Analyze security documents using Claude via AWS Bedrock."""

    # Retry configuration for rate limiting
    MAX_RETRIES = 5
    BASE_DELAY = 2  # seconds
    MAX_DELAY = 60  # seconds

    def __init__(self):
        self._client = None
        self._use_bearer_token = bool(settings.aws_bearer_token_bedrock)

    @property
    def client(self):
        """Lazy initialization of Bedrock client (only used for IAM auth)."""
        if self._client is None and not self._use_bearer_token:
            config = Config(
                connect_timeout=30,
                read_timeout=180,  # Increased for longer documents
                retries={"max_attempts": 0},  # We handle retries ourselves
            )
            self._client = boto3.client(
                "bedrock-runtime",
                region_name=settings.aws_region,
                config=config,
            )
        return self._client

    def _get_bedrock_url(self) -> str:
        """Get the Bedrock runtime API URL for the configured region."""
        return f"https://bedrock-runtime.{settings.aws_region}.amazonaws.com"

    async def _invoke_with_bearer_token(self, model_id: str, body: dict) -> dict:
        """Invoke Bedrock model using bearer token authentication."""
        url = f"{self._get_bedrock_url()}/model/{model_id}/invoke"

        headers = {
            "Authorization": f"Bearer {settings.aws_bearer_token_bedrock}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient(timeout=180.0) as client:
            response = await client.post(url, json=body, headers=headers)

            if response.status_code == 429:
                raise ClientError(
                    {"Error": {"Code": "ThrottlingException", "Message": "Rate limited"}},
                    "InvokeModel"
                )
            elif response.status_code == 503:
                raise ClientError(
                    {"Error": {"Code": "ServiceUnavailableException", "Message": "Service unavailable"}},
                    "InvokeModel"
                )
            elif response.status_code != 200:
                raise Exception(f"Bedrock API error: {response.status_code} - {response.text}")

            return response.json()

    async def _retry_with_backoff(self, func, *args, **kwargs):
        """Execute a function with exponential backoff on throttling errors."""
        last_exception = None

        for attempt in range(self.MAX_RETRIES):
            try:
                return func(*args, **kwargs)
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")

                if error_code in ("ThrottlingException", "TooManyRequestsException", "ServiceUnavailableException"):
                    last_exception = e
                    # Exponential backoff with jitter
                    delay = min(self.MAX_DELAY, self.BASE_DELAY * (2 ** attempt))
                    jitter = random.uniform(0, delay * 0.5)
                    wait_time = delay + jitter

                    print(f"Rate limited (attempt {attempt + 1}/{self.MAX_RETRIES}), waiting {wait_time:.1f}s...")
                    await asyncio.sleep(wait_time)
                else:
                    # Non-throttling error, don't retry
                    raise

        # All retries exhausted
        raise last_exception or Exception("Max retries exceeded")

    # Control framework reference data for Big 4-style analysis
    FRAMEWORK_CONTROLS = {
        "SOC2": {
            "CC1": "Control Environment",
            "CC2": "Communication and Information",
            "CC3": "Risk Assessment",
            "CC4": "Monitoring Activities",
            "CC5": "Control Activities",
            "CC6": "Logical and Physical Access Controls",
            "CC7": "System Operations",
            "CC8": "Change Management",
            "CC9": "Risk Mitigation",
            "A1": "Availability",
            "C1": "Confidentiality",
            "PI1": "Processing Integrity",
            "P1": "Privacy",
        },
        "ISO27001": {
            "A.5": "Information Security Policies",
            "A.6": "Organization of Information Security",
            "A.7": "Human Resource Security",
            "A.8": "Asset Management",
            "A.9": "Access Control",
            "A.10": "Cryptography",
            "A.11": "Physical and Environmental Security",
            "A.12": "Operations Security",
            "A.13": "Communications Security",
            "A.14": "System Acquisition, Development and Maintenance",
            "A.15": "Supplier Relationships",
            "A.16": "Information Security Incident Management",
            "A.17": "Business Continuity Management",
            "A.18": "Compliance",
        },
        "NIST_CSF": {
            "ID.AM": "Asset Management",
            "ID.BE": "Business Environment",
            "ID.GV": "Governance",
            "ID.RA": "Risk Assessment",
            "ID.RM": "Risk Management Strategy",
            "ID.SC": "Supply Chain Risk Management",
            "PR.AC": "Identity Management and Access Control",
            "PR.AT": "Awareness and Training",
            "PR.DS": "Data Security",
            "PR.IP": "Information Protection Processes",
            "PR.MA": "Maintenance",
            "PR.PT": "Protective Technology",
            "DE.AE": "Anomalies and Events",
            "DE.CM": "Security Continuous Monitoring",
            "DE.DP": "Detection Processes",
            "RS.RP": "Response Planning",
            "RS.CO": "Communications",
            "RS.AN": "Analysis",
            "RS.MI": "Mitigation",
            "RS.IM": "Improvements",
            "RC.RP": "Recovery Planning",
            "RC.IM": "Improvements",
            "RC.CO": "Communications",
        },
        "HIPAA": {
            "164.308(a)(1)": "Security Management Process",
            "164.308(a)(2)": "Assigned Security Responsibility",
            "164.308(a)(3)": "Workforce Security",
            "164.308(a)(4)": "Information Access Management",
            "164.308(a)(5)": "Security Awareness and Training",
            "164.308(a)(6)": "Security Incident Procedures",
            "164.308(a)(7)": "Contingency Plan",
            "164.308(a)(8)": "Evaluation",
            "164.310(a)": "Facility Access Controls",
            "164.310(b)": "Workstation Use",
            "164.310(c)": "Workstation Security",
            "164.310(d)": "Device and Media Controls",
            "164.312(a)": "Access Control",
            "164.312(b)": "Audit Controls",
            "164.312(c)": "Integrity",
            "164.312(d)": "Person or Entity Authentication",
            "164.312(e)": "Transmission Security",
        },
        "GDPR": {
            "Art.5": "Principles of Processing",
            "Art.6": "Lawfulness of Processing",
            "Art.7": "Conditions for Consent",
            "Art.12-14": "Transparency and Information",
            "Art.15-22": "Data Subject Rights",
            "Art.24": "Responsibility of Controller",
            "Art.25": "Data Protection by Design",
            "Art.28": "Processor Requirements",
            "Art.30": "Records of Processing",
            "Art.32": "Security of Processing",
            "Art.33-34": "Breach Notification",
            "Art.35": "Data Protection Impact Assessment",
            "Art.37-39": "Data Protection Officer",
            "Art.44-49": "International Transfers",
        },
        "PCI_DSS": {
            "Req.1": "Install and Maintain Network Security Controls",
            "Req.2": "Apply Secure Configurations",
            "Req.3": "Protect Stored Account Data",
            "Req.4": "Protect Cardholder Data with Strong Cryptography",
            "Req.5": "Protect Against Malicious Software",
            "Req.6": "Develop and Maintain Secure Systems",
            "Req.7": "Restrict Access by Business Need to Know",
            "Req.8": "Identify Users and Authenticate Access",
            "Req.9": "Restrict Physical Access",
            "Req.10": "Log and Monitor Access",
            "Req.11": "Test Security Regularly",
            "Req.12": "Support Information Security with Policies",
        },
    }

    async def analyze_document(
        self,
        document_text: str,
        filename: str,
        frameworks: list[str],
        is_soc2: bool = False,
    ) -> dict:
        """
        Analyze a document for security compliance using Big 4-style methodology.

        Returns:
            dict with 'findings', 'framework_coverage', 'strengths'
        """
        # Build framework control references for the prompt
        framework_refs = []
        for fw in frameworks:
            if fw in self.FRAMEWORK_CONTROLS:
                controls = self.FRAMEWORK_CONTROLS[fw]
                control_list = "\n".join([f"    - {k}: {v}" for k, v in controls.items()])
                framework_refs.append(f"  {fw}:\n{control_list}")

        frameworks_str = ", ".join(frameworks)
        framework_controls_str = "\n".join(framework_refs) if framework_refs else "Standard control frameworks"

        doc_type = "SOC2 Type 2 audit report" if is_soc2 else "security documentation"
        soc2_instructions = """
SOC2 SPECIFIC ANALYSIS REQUIREMENTS:
- Examine the auditor's opinion (unqualified, qualified, adverse, disclaimer)
- Identify ALL control exceptions, deviations, and management responses
- Note the audit period and any gaps in control operation
- Evaluate complementary user entity controls (CUECs)
- Assess subservice organization controls (if applicable)
- Review management's description of the system
- Identify any carve-outs or scope limitations
- Note testing procedures performed by the auditor""" if is_soc2 else ""

        prompt = f"""You are a Senior Manager at a Big 4 accounting firm conducting a third-party risk assessment.
Apply rigorous professional skepticism and thoroughness in your analysis.

ENGAGEMENT CONTEXT:
- Document Under Review: {filename}
- Document Classification: {doc_type}
- Frameworks for Evaluation: {frameworks_str}
- Assessment Methodology: Risk-based control testing with substantive procedures

APPLICABLE CONTROL FRAMEWORKS:
{framework_controls_str}
{soc2_instructions}

DOCUMENT CONTENT:
{document_text[:80000]}

Perform a comprehensive analysis following Big 4 methodology and provide your assessment in the following JSON format:

{{
    "document_type": "Specific classification (e.g., 'SOC 2 Type II Report - Trust Services Criteria', 'Information Security Policy v2.3', 'Business Continuity Plan')",
    "document_scope": "What systems, processes, or services this document covers",
    "audit_period": "Date range covered if applicable, or 'Point-in-time' for policies",

    "findings": [
        {{
            "finding_id": "F-001 (sequential)",
            "severity": "critical|high|medium|low",
            "category": "access_control|encryption|incident_response|audit_logging|data_protection|network_security|vendor_management|business_continuity|change_management|physical_security|hr_security|compliance|privacy|other",
            "title": "Concise finding title",
            "description": "Detailed description of the control gap, deficiency, or risk. Include specific details about what is missing or inadequate.",
            "root_cause": "Underlying reason for the gap (e.g., 'Policy not updated to reflect current technology stack', 'Lack of formal process')",
            "business_impact": "Potential business consequences if not addressed (e.g., 'Unauthorized access could result in data breach affecting customer PII')",
            "likelihood": "high|medium|low - probability of risk materializing",
            "control_references": ["List specific control IDs from frameworks, e.g., 'SOC2:CC6.1', 'ISO27001:A.9.2.3', 'NIST:PR.AC-1'"],
            "evidence": "Direct quote or specific reference from document supporting this finding",
            "recommendation": "Specific, actionable remediation steps",
            "remediation_effort": "low|medium|high - estimated effort to remediate",
            "remediation_timeline": "Suggested timeframe (e.g., 'Immediate (0-30 days)', '30-60 days', '60-90 days', '90+ days')",
            "management_response_suggestion": "Recommended management response for the finding"
        }}
    ],

    "strengths": [
        {{
            "category": "Category of strength",
            "title": "Brief title",
            "description": "Detailed description of what the vendor does well and why it's significant",
            "control_references": ["Applicable control IDs this satisfies"],
            "evidence": "Quote or reference from document",
            "maturity_indicator": "Whether this indicates mature security practices"
        }}
    ],

    "framework_coverage": {{
        "framework_name": {{
            "coverage_percentage": 0-100,
            "maturity_level": "Initial|Developing|Defined|Managed|Optimizing",
            "implemented_controls": [
                {{"control_id": "Control ID", "control_name": "Name", "implementation_status": "Fully Implemented", "evidence_quality": "strong|moderate|weak"}}
            ],
            "partial_controls": [
                {{"control_id": "Control ID", "control_name": "Name", "gap_description": "What's missing", "evidence_quality": "strong|moderate|weak"}}
            ],
            "missing_controls": [
                {{"control_id": "Control ID", "control_name": "Name", "risk_if_unaddressed": "Brief risk statement"}}
            ],
            "not_applicable": ["List any controls not applicable with justification"]
        }}
    }},

    "risk_assessment": {{
        "inherent_risk_rating": "Critical|High|Medium|Low",
        "control_effectiveness": "Strong|Adequate|Needs Improvement|Weak",
        "residual_risk_rating": "Critical|High|Medium|Low",
        "risk_trend": "Increasing|Stable|Decreasing",
        "key_risk_indicators": ["List of KRIs identified"]
    }},

    "testing_procedures_performed": [
        "List of assessment procedures performed (e.g., 'Reviewed policy documentation for completeness', 'Evaluated access control configurations', 'Assessed encryption standards')"
    ],

    "limitations_and_caveats": [
        "Any limitations in the assessment (e.g., 'Assessment based solely on documentation provided', 'Unable to verify technical implementation')"
    ],

    "executive_summary": "3-4 sentence professional summary suitable for C-level executives, summarizing overall posture, key risks, and recommended actions"
}}

ANALYSIS GUIDELINES:
1. Apply professional skepticism - don't assume controls are effective without evidence
2. Map ALL findings to specific control framework requirements
3. Only report findings for ACTUAL gaps - if a control is implemented, add it to strengths
4. For SOC2 reports, any auditor-noted exceptions are HIGH or CRITICAL findings
5. Differentiate between control design gaps and control operating effectiveness gaps
6. Consider compensating controls that may mitigate identified risks
7. Provide specific, actionable recommendations (not generic advice)
8. Base severity on business impact and likelihood:
   - CRITICAL: Immediate exploitation risk, regulatory violation, or significant data exposure
   - HIGH: Material weakness requiring urgent remediation within 30 days
   - MEDIUM: Significant deficiency requiring remediation within 90 days
   - LOW: Opportunity for improvement, best practice recommendation
9. If the document demonstrates strong security practices, reflect this with fewer findings and higher coverage scores
10. Evidence quality matters - note when controls are well-documented vs. vaguely referenced

Respond ONLY with valid JSON, no additional text or markdown formatting."""

        try:
            response = await self._invoke_model(prompt, max_tokens=16000)

            # Parse the JSON response
            result = json.loads(response)
            return {
                "success": True,
                "document_type": result.get("document_type", "Unknown"),
                "document_scope": result.get("document_scope", ""),
                "audit_period": result.get("audit_period", ""),
                "findings": result.get("findings", []),
                "strengths": result.get("strengths", []),
                "framework_coverage": result.get("framework_coverage", {}),
                "risk_assessment": result.get("risk_assessment", {}),
                "testing_procedures": result.get("testing_procedures_performed", []),
                "limitations": result.get("limitations_and_caveats", []),
                "executive_summary": result.get("executive_summary", ""),
            }

        except json.JSONDecodeError as e:
            # Try to extract JSON from response if it has extra text
            try:
                import re
                json_match = re.search(r'\{[\s\S]*\}', response)
                if json_match:
                    result = json.loads(json_match.group())
                    return {
                        "success": True,
                        "document_type": result.get("document_type", "Unknown"),
                        "document_scope": result.get("document_scope", ""),
                        "audit_period": result.get("audit_period", ""),
                        "findings": result.get("findings", []),
                        "strengths": result.get("strengths", []),
                        "framework_coverage": result.get("framework_coverage", {}),
                        "risk_assessment": result.get("risk_assessment", {}),
                        "testing_procedures": result.get("testing_procedures_performed", []),
                        "limitations": result.get("limitations_and_caveats", []),
                        "executive_summary": result.get("executive_summary", ""),
                    }
            except:
                pass

            return {
                "success": False,
                "error": f"Failed to parse AI response: {str(e)}",
                "findings": [],
                "strengths": [],
                "framework_coverage": {},
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "findings": [],
                "strengths": [],
                "framework_coverage": {},
            }

    async def _invoke_model(self, prompt: str, max_tokens: int = 8000) -> str:
        """Invoke the Bedrock model and return the response text with retry logic."""
        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "temperature": 0.2,  # Lower temperature for more consistent analysis
            "messages": [{"role": "user", "content": prompt}],
        }

        if self._use_bearer_token:
            # Use bearer token authentication via HTTP
            return await self._invoke_with_bearer_token_retry(request_body)
        else:
            # Use boto3 with IAM credentials
            def make_request():
                return self.client.invoke_model(
                    modelId=settings.bedrock_model_id,
                    body=json.dumps(request_body),
                    contentType="application/json",
                    accept="application/json",
                )

            response = await self._retry_with_backoff(make_request)
            response_body = json.loads(response["body"].read())
            return response_body["content"][0]["text"]

    async def _invoke_with_bearer_token_retry(self, request_body: dict) -> str:
        """Invoke model using bearer token with retry logic."""
        last_exception = None

        for attempt in range(self.MAX_RETRIES):
            try:
                response = await self._invoke_with_bearer_token(
                    settings.bedrock_model_id,
                    request_body
                )
                return response["content"][0]["text"]
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code in ("ThrottlingException", "TooManyRequestsException", "ServiceUnavailableException"):
                    last_exception = e
                    delay = min(self.MAX_DELAY, self.BASE_DELAY * (2 ** attempt))
                    jitter = random.uniform(0, delay * 0.5)
                    wait_time = delay + jitter
                    print(f"Rate limited (attempt {attempt + 1}/{self.MAX_RETRIES}), waiting {wait_time:.1f}s...")
                    await asyncio.sleep(wait_time)
                else:
                    raise
            except Exception as e:
                # For non-ClientError exceptions, check if it's a rate limit response
                error_msg = str(e).lower()
                if "429" in error_msg or "throttl" in error_msg or "rate limit" in error_msg:
                    last_exception = e
                    delay = min(self.MAX_DELAY, self.BASE_DELAY * (2 ** attempt))
                    jitter = random.uniform(0, delay * 0.5)
                    wait_time = delay + jitter
                    print(f"Rate limited (attempt {attempt + 1}/{self.MAX_RETRIES}), waiting {wait_time:.1f}s...")
                    await asyncio.sleep(wait_time)
                else:
                    raise

        raise last_exception or Exception("Max retries exceeded")

    async def generate_consolidated_summary(
        self,
        all_findings: list[dict],
        all_strengths: list[dict],
        framework_coverage: dict,
        document_count: int,
        soc2_count: int,
        vendor_name: Optional[str] = None,
    ) -> str:
        """Generate a comprehensive executive summary from consolidated analysis."""

        # Count findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in all_findings:
            sev = f.get("severity", "").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Count findings by category
        category_counts = {}
        for f in all_findings:
            cat = f.get("category", "other")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Calculate average coverage and maturity
        coverages = []
        maturity_levels = []
        for fw_name, fw_data in framework_coverage.items():
            if isinstance(fw_data, dict):
                if "coverage_percentage" in fw_data:
                    coverages.append(fw_data["coverage_percentage"])
                if "maturity_level" in fw_data:
                    maturity_levels.append(fw_data["maturity_level"])
        avg_coverage = sum(coverages) / len(coverages) if coverages else 0

        # Determine overall risk rating
        if severity_counts['critical'] > 0:
            overall_risk = "Critical"
        elif severity_counts['high'] > 2:
            overall_risk = "High"
        elif severity_counts['high'] > 0 or severity_counts['medium'] > 3:
            overall_risk = "Medium"
        else:
            overall_risk = "Low"

        vendor_str = f"for {vendor_name}" if vendor_name else ""

        prompt = f"""You are a Senior Partner at a Big 4 firm writing an executive summary for a board-level audience.

THIRD-PARTY RISK ASSESSMENT RESULTS {vendor_str.upper()}

ASSESSMENT SCOPE:
- Documents Analyzed: {document_count}
- SOC 2 Type II Reports Reviewed: {soc2_count}
- Frameworks Evaluated: {', '.join(framework_coverage.keys()) if framework_coverage else 'Multiple'}

QUANTITATIVE METRICS:
- Average Framework Coverage: {avg_coverage:.0f}%
- Overall Risk Rating: {overall_risk}

FINDINGS BY SEVERITY:
- Critical Findings: {severity_counts['critical']}
- High Findings: {severity_counts['high']}
- Medium Findings: {severity_counts['medium']}
- Low/Informational: {severity_counts['low']}
- Total Findings: {sum(severity_counts.values())}

FINDINGS BY CATEGORY:
{json.dumps(category_counts, indent=2)}

KEY FINDINGS REQUIRING IMMEDIATE ATTENTION:
{json.dumps([f for f in all_findings if f.get('severity', '').lower() in ['critical', 'high']][:5], indent=2) if any(f.get('severity', '').lower() in ['critical', 'high'] for f in all_findings) else "No critical or high severity findings identified."}

NOTABLE SECURITY STRENGTHS:
{json.dumps(all_strengths[:5], indent=2) if all_strengths else "Limited strengths documented in provided materials."}

Write a comprehensive executive summary (2-3 paragraphs) suitable for presentation to the Board Risk Committee. The summary should:

1. OPENING STATEMENT: Provide an overall assessment opinion (e.g., "Based on our review... the vendor demonstrates [mature/developing/inadequate] security practices...")

2. KEY OBSERVATIONS:
   - Highlight the most significant findings requiring management attention
   - Note any material weaknesses or significant deficiencies
   - Acknowledge areas of strength that reduce third-party risk

3. RISK-BASED RECOMMENDATION:
   - Provide a clear recommendation (e.g., "approve with conditions", "approve with monitoring", "requires remediation before engagement", "do not recommend")
   - Specify any conditions or monitoring requirements
   - Suggest timeline for re-assessment if applicable

4. PROFESSIONAL TONE:
   - Use language appropriate for C-suite and board members
   - Be direct and specific, avoid generic statements
   - Quantify risk where possible

Respond with ONLY the executive summary text. Do not include JSON, headers, or formatting markers."""

        try:
            return await self._invoke_model(prompt, max_tokens=2000)
        except Exception as e:
            # Fallback to generated summary
            risk_statement = {
                "Critical": "requires immediate attention before proceeding with the engagement",
                "High": "presents elevated risk requiring remediation commitments",
                "Medium": "demonstrates adequate controls with opportunities for improvement",
                "Low": "demonstrates mature security practices aligned with industry standards"
            }.get(overall_risk, "requires further evaluation")

            return (
                f"This third-party risk assessment analyzed {document_count} document(s) "
                f"{f'provided by {vendor_name}' if vendor_name else 'from the vendor'}"
                f"{f', including {soc2_count} SOC 2 Type II report(s)' if soc2_count > 0 else ''}. "
                f"The vendor demonstrates {'strong' if avg_coverage >= 80 else 'moderate' if avg_coverage >= 60 else 'developing'} "
                f"compliance maturity with an average framework coverage of {avg_coverage:.0f}%. "
                f"Our assessment identified {len(all_findings)} finding(s), including {severity_counts['critical']} critical "
                f"and {severity_counts['high']} high severity issues that {risk_statement}. "
                f"{'We recommend approval with standard monitoring.' if overall_risk == 'Low' else 'Management review of remediation plans is recommended before finalizing the engagement.'}"
            )


# Singleton instance
ai_analyzer = AIAnalyzer()
