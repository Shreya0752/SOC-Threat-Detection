"""
Response Recommendations Engine for Milestone 3 (`backend/risk/recommendations.py`).
Provides prioritized, guidance-only response playbooks tailored to detected threat types
and attack scenarios without performing unauthorized automatic destructive actions.
"""
from typing import List, Dict, Any

RECOMMENDATION_PLAYBOOKS: Dict[str, List[str]] = {
    "brute force": [
        "Temporarily lock the affected account or require identity re-verification",
        "Investigate and correlate the attacking source IP against external threat feeds",
        "Review comprehensive authentication logs for credential stuffing or spray patterns",
        "Enforce Multi-Factor Authentication (MFA) on affected endpoints"
    ],
    "malware": [
        "Isolate affected endpoint from the corporate network segment",
        "Initiate comprehensive antimalware and EDR signature scan",
        "Investigate file hashes and execute sandbox analysis",
        "Audit running processes and persistence registry keys for malicious payloads"
    ],
    "data exfiltration": [
        "Investigate destination IP / external domain for malicious hosting indicators",
        "Restrict outbound connections from affected internal asset",
        "Review data transfer logs, file access audits, and egress volumes",
        "Escalate incident to Incident Response (IR) team for containment"
    ],
    "privilege escalation": [
        "Audit user account permissions and terminate unauthorized active sessions",
        "Revoke elevated administrative privileges assigned to non-admin identities",
        "Inspect system event logs for unauthorized privilege elevation or token duplication",
        "Enforce strict least-privilege role-based access control policies"
    ],
    "sql injection": [
        "Inspect Web Application Firewall (WAF) logs for malicious SQL payload signatures",
        "Block attacking source IP address at the perimeter firewall / reverse proxy",
        "Review affected database audit trails for unauthorized query executions",
        "Apply parameterization and input sanitization patches to affected web application code"
    ],
    "phishing": [
        "Isolate affected employee inbox and revoke active OAuth tokens/sessions",
        "Inspect email headers, sender reputation, and embedded phishing URLs",
        "Block malicious domains and attachments across the secure email gateway",
        "Alert SOC team for organization-wide email sweep and user awareness warning"
    ],
    "port scan": [
        "Analyze scan footprint and source IP address range across firewall logs",
        "Ensure all non-essential perimeter ports and services are closed",
        "Verify intrusion prevention system (IPS) rate-limiting rules are enforced",
        "Check destination hosts for unauthorized service discovery responses"
    ],
    "multi-stage attack": [
        "Escalate immediately to SOC Tier 2 Lead and Incident Response Team",
        "Isolate affected target asset and revoke compromised user credentials",
        "Collect forensic memory dumps and network packet captures across all attack stages",
        "Perform end-to-end timeline reconstruction across MITRE ATT&CK kill chain"
    ]
}

DEFAULT_PLAYBOOK = [
    "Conduct deep-dive investigation into affected user account and target asset",
    "Inspect telemetry logs and network flows around event timestamps",
    "Verify integrity of security controls and endpoint monitoring agents",
    "Document findings and escalate to SOC Lead if anomalous activity persists"
]

class RecommendationEngine:
    """Generates context-aware, guidance-only analyst response playbooks."""

    @classmethod
    def get_recommendations(cls, threat_type: str = "", priority: str = "Medium", threat_severity: str = "Low") -> List[str]:
        """
        Retrieves recommended action steps for the specified threat type and severity.
        These recommendations serve as analyst guidance, not automatic scripts.
        """
        clean_type = str(threat_type).strip().lower()

        matched_key = None
        for key in RECOMMENDATION_PLAYBOOKS:
            if key in clean_type:
                matched_key = key
                break

        actions = list(RECOMMENDATION_PLAYBOOKS.get(matched_key, DEFAULT_PLAYBOOK))

        # Add urgency escalation step for Critical priority incidents
        if str(priority).capitalize() == "Critical" or str(threat_severity).capitalize() == "Critical":
            if not any("Escalate" in a for a in actions):
                actions.append("Escalate incident directly to SOC Incident Lead for immediate containment")

        return actions
