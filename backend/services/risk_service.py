"""
Risk Service Module for Milestone 3 (`backend/services/risk_service.py`).
Orchestrates risk calculations, high-risk incident retrieval, and risk summary metrics.
"""
import os
import sys
from typing import Dict, Any, List, Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database.prediction_repository import PredictionRepository
from backend.database.incident_repository import IncidentRepository
from backend.risk.risk_score import RiskScoreEngine
from backend.risk.prioritization import ThreatPrioritization

class RiskService:
    """Provides high-level business logic for risk scoring and summary telemetry."""

    @staticmethod
    def calculate_risk(payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates risk score for an event_id or raw event payload.
        """
        event_id = payload.get("event_id")
        event_data = {}

        if event_id:
            fetched = PredictionRepository.get_event_with_prediction(event_id)
            if fetched:
                event_data = fetched

        # Overlay payload values onto event_data
        for k, v in payload.items():
            if v is not None:
                event_data[k] = v

        threat_severity = event_data.get("threat_severity") or event_data.get("severity") or event_data.get("m2_severity") or "Low"
        ml_confidence = float(event_data.get("confidence_score") or 50.0)
        asset_name = event_data.get("asset_name") or "Unknown"
        asset_crit = event_data.get("criticality") or ""
        cvss_score = float(event_data.get("cvss_score") or 0.0)
        vuln_id = event_data.get("vulnerability_id") or ""
        threat_match = bool(event_data.get("threat_match") or False)
        malicious_ip_flag = int(event_data.get("malicious_ip_flag") or 0)
        threat_indicator = bool(event_data.get("threat_indicator") or False)
        threat_severity_feed = str(event_data.get("threat_severity_feed") or event_data.get("feed_severity") or "None")
        threat_name = str(event_data.get("threat_name") or "")

        result = RiskScoreEngine.calculate_risk(
            threat_severity_input=threat_severity,
            ml_confidence=ml_confidence,
            asset_name=asset_name,
            asset_criticality_str=asset_crit,
            cvss_score=cvss_score,
            vulnerability_id=vuln_id,
            threat_match=threat_match,
            malicious_ip_flag=malicious_ip_flag,
            threat_indicator=threat_indicator,
            threat_severity_feed=threat_severity_feed,
            threat_name=threat_name,
            related_events_count=int(payload.get("related_events_count", 1))
        )
        result["risk_level"] = result.get("priority")
        result["reasons"] = result.get("explainability", [])
        if event_id:
            result["event_id"] = event_id
        return result

    @staticmethod
    def get_high_risk_threats(limit: int = 25) -> Dict[str, Any]:
        """Retrieves prioritized list of high and critical risk threats."""
        incidents_data = IncidentRepository.get_incidents(limit=limit)
        high_risk_items = [
            inc for inc in incidents_data.get("incidents", [])
            if inc.get("priority") in ["Critical", "High"]
        ]
        from backend.services.incident_service import IncidentService
        for item in high_risk_items:
            IncidentService._enrich_incident_aliases(item)
        return {
            "total_high_risk": len(high_risk_items),
            "high_risk_threats": high_risk_items
        }

    @staticmethod
    def get_risk_summary() -> Dict[str, Any]:
        """
        Calculates comprehensive M3 risk telemetry:
        - Incident distribution: Critical, High, Medium, Low
        - Total incidents & Open incidents count
        - Average risk score
        - Top risk factors across active incidents
        - Storage connectivity status
        """
        all_incidents_data = IncidentRepository.get_incidents(limit=0)
        incidents = all_incidents_data.get("incidents", [])
        total = len(incidents)

        distribution = ThreatPrioritization.get_priority_distribution(incidents)
        open_count = sum(1 for inc in incidents if inc.get("status") in ["Open", "Investigating"])

        scores = [inc.get("risk_score", 0) for inc in incidents]
        avg_score = round(sum(scores) / total, 1) if total > 0 else 0.0

        connectivity = IncidentRepository.get_connectivity_status()

        return {
            "total_incidents": total,
            "open_incidents": open_count,
            "resolved_incidents": sum(1 for inc in incidents if inc.get("status") == "Resolved"),
            "critical_count": distribution.get("Critical", 0),
            "high_count": distribution.get("High", 0),
            "medium_count": distribution.get("Medium", 0),
            "low_count": distribution.get("Low", 0),
            "average_risk_score": avg_score,
            "priority_distribution": distribution,
            "database_status": connectivity
        }
