"""
Threat Prioritization Engine for Milestone 3 (`backend/risk/prioritization.py`).
Implements dynamic risk-based ranking to answer the core SOC analyst question:
"Which detected threat should the security analyst investigate first, and why?"
"""
from typing import List, Dict, Any

class ThreatPrioritization:
    """Prioritizes and ranks security incidents based on descending risk scores."""

    @staticmethod
    def rank_incidents(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sorts incidents dynamically by risk_score in descending order,
        assigning priority ranks and investigation order.
        """
        if not incidents:
            return []

        # Sort primary: risk_score descending, secondary: created_at descending
        sorted_incidents = sorted(
            incidents,
            key=lambda inc: (inc.get("risk_score", 0), inc.get("created_at", "")),
            reverse=True
        )

        ranked = []
        for idx, inc in enumerate(sorted_incidents, start=1):
            inc_copy = dict(inc)
            inc_copy["priority_rank"] = idx
            inc_copy["investigation_urgency"] = (
                "Immediate Action Required" if inc_copy.get("risk_score", 0) >= 81 else
                "High Urgency" if inc_copy.get("risk_score", 0) >= 61 else
                "Elevated Monitoring" if inc_copy.get("risk_score", 0) >= 41 else
                "Routine Review"
            )
            ranked.append(inc_copy)

        return ranked

    @staticmethod
    def get_priority_distribution(incidents: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculates incident count per priority tier."""
        dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for inc in incidents:
            prio = inc.get("priority", "Low").capitalize()
            if prio in dist:
                dist[prio] += 1
            else:
                dist["Low"] += 1
        return dist

    @staticmethod
    def get_top_priority(incidents: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
        """Returns top N urgent incidents for dashboard highlights."""
        ranked = ThreatPrioritization.rank_incidents(incidents)
        return ranked[:limit]
