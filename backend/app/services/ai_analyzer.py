"""AI-powered document analysis service using AWS Bedrock."""

import json
from typing import Optional

import boto3
from botocore.config import Config

from app.config import settings


class AIAnalyzer:
    """Analyze security documents using Claude via AWS Bedrock."""

    def __init__(self):
        self._client = None

    @property
    def client(self):
        """Lazy initialization of Bedrock client."""
        if self._client is None:
            config = Config(
                connect_timeout=30,
                read_timeout=120,
                retries={"max_attempts": 2},
            )
            self._client = boto3.client(
                "bedrock-runtime",
                region_name=settings.aws_region,
                config=config,
            )
        return self._client

    async def analyze_document(
        self,
        document_text: str,
        filename: str,
        frameworks: list[str],
        is_soc2: bool = False,
    ) -> dict:
        """
        Analyze a document for security compliance.

        Returns:
            dict with 'findings', 'framework_coverage', 'strengths'
        """
        # Build the analysis prompt
        frameworks_str = ", ".join(frameworks)
        doc_type = "SOC2 Type 2 audit report" if is_soc2 else "security documentation"

        prompt = f"""You are a security compliance expert analyzing vendor {doc_type}.
Analyze the following document and provide a structured assessment.

DOCUMENT NAME: {filename}
FRAMEWORKS TO EVALUATE: {frameworks_str}

DOCUMENT CONTENT:
{document_text[:80000]}

Please analyze this document and provide your assessment in the following JSON format:
{{
    "document_type": "string describing what type of document this is",
    "findings": [
        {{
            "severity": "critical|high|medium|low",
            "category": "access_control|encryption|incident_response|audit|data_protection|network_security|vendor_management|business_continuity|compliance|other",
            "title": "brief title of the finding",
            "description": "detailed description of the gap or issue",
            "recommendation": "specific recommendation to address this",
            "evidence": "quote or reference from the document supporting this finding"
        }}
    ],
    "strengths": [
        {{
            "category": "category name",
            "title": "brief title",
            "description": "what the vendor does well",
            "evidence": "quote or reference from document"
        }}
    ],
    "framework_coverage": {{
        "framework_name": {{
            "coverage_percentage": 0-100,
            "implemented_controls": ["list of controls that are implemented"],
            "partial_controls": ["list of controls partially implemented"],
            "missing_controls": ["list of controls not addressed"]
        }}
    }},
    "executive_summary": "2-3 sentence summary of the vendor's security posture based on this document"
}}

IMPORTANT GUIDELINES:
1. Only report findings that are actually gaps or issues based on the document content
2. If a control IS implemented (like MFA), do NOT report it as missing - add it to strengths instead
3. Be specific and cite evidence from the document
4. For SOC2 reports, pay special attention to audit exceptions and control deficiencies
5. Severity levels:
   - critical: Immediate risk, fundamental security control missing
   - high: Significant gap that should be addressed soon
   - medium: Notable issue but not urgent
   - low: Minor improvement opportunity
6. If the document shows strong security practices, reflect that in lower finding counts and higher coverage

Respond ONLY with valid JSON, no additional text."""

        try:
            response = await self._invoke_model(prompt)

            # Parse the JSON response
            result = json.loads(response)
            return {
                "success": True,
                "document_type": result.get("document_type", "Unknown"),
                "findings": result.get("findings", []),
                "strengths": result.get("strengths", []),
                "framework_coverage": result.get("framework_coverage", {}),
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
                        "findings": result.get("findings", []),
                        "strengths": result.get("strengths", []),
                        "framework_coverage": result.get("framework_coverage", {}),
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

    async def _invoke_model(self, prompt: str) -> str:
        """Invoke the Bedrock model and return the response text."""
        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 8000,
            "temperature": 0.2,  # Lower temperature for more consistent analysis
            "messages": [{"role": "user", "content": prompt}],
        }

        response = self.client.invoke_model(
            modelId=settings.bedrock_model_id,
            body=json.dumps(request_body),
            contentType="application/json",
            accept="application/json",
        )

        response_body = json.loads(response["body"].read())
        return response_body["content"][0]["text"]

    async def generate_consolidated_summary(
        self,
        all_findings: list[dict],
        all_strengths: list[dict],
        framework_coverage: dict,
        document_count: int,
        soc2_count: int,
    ) -> str:
        """Generate an executive summary from consolidated analysis."""

        # Count findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in all_findings:
            sev = f.get("severity", "").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Calculate average coverage
        coverages = []
        for fw_name, fw_data in framework_coverage.items():
            if isinstance(fw_data, dict) and "coverage_percentage" in fw_data:
                coverages.append(fw_data["coverage_percentage"])
        avg_coverage = sum(coverages) / len(coverages) if coverages else 0

        prompt = f"""Based on the following security assessment data, write a professional 3-4 sentence executive summary:

Documents Analyzed: {document_count} (including {soc2_count} SOC2 Type 2 reports)
Average Framework Coverage: {avg_coverage:.0f}%

Findings Summary:
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}

Key Findings:
{json.dumps(all_findings[:5], indent=2) if all_findings else "No significant findings"}

Key Strengths:
{json.dumps(all_strengths[:5], indent=2) if all_strengths else "Limited strengths identified"}

Write a balanced, professional executive summary that:
1. States the overall compliance posture
2. Highlights key strengths if any exist
3. Notes critical gaps if any exist
4. Provides a risk-based recommendation

Respond with ONLY the summary text, no JSON or formatting."""

        try:
            return await self._invoke_model(prompt)
        except Exception as e:
            # Fallback to generated summary
            return (
                f"This assessment analyzed {document_count} document(s)"
                f"{f', including {soc2_count} SOC2 Type 2 report(s)' if soc2_count > 0 else ''}. "
                f"The vendor demonstrates {'strong' if avg_coverage >= 80 else 'moderate' if avg_coverage >= 60 else 'developing'} "
                f"compliance maturity with an average coverage of {avg_coverage:.0f}%. "
                f"{len(all_findings)} findings were identified requiring attention."
            )


# Singleton instance
ai_analyzer = AIAnalyzer()
