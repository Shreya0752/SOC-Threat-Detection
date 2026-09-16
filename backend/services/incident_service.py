"""
Incident Service Module for Milestone 3 (`backend/services/incident_service.py`).
Implements automatic bootstrap correlation from M1/M2 data, multi-stage attack chain extraction,
incident querying, and status updates.
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
from backend.risk.correlation import EventCorrelationEngine
from backend.risk.recommendations import RecommendationEngine
from backend.risk.prioritization import ThreatPrioritization

class IncidentService:
    """Coordinates incident creation, correlation, queries, and attack chain extraction."""

    @classmethod
    def bootstrap_incidents_from_data(cls, force_reseed: bool = False) -> int:
        """
        Extracts correlated incidents from existing M1 events and M2 threat predictions.
        Builds real multi-stage attack scenarios and persists them without generating fake data.
        """
        existing_count = IncidentRepository.count_incidents()
        if existing_count > 0 and not force_reseed:
            print(f"[IncidentService] Found {existing_count} existing incidents in persistence layer.")
            return existing_count

        print("[IncidentService] Correlating M2 threat predictions into security incidents...")
        events = PredictionRepository.get_all_events_for_correlation()
        if not events:
            print("[IncidentService Warning] No events found in database to correlate.")
            return 0

        # Filter events that have anomalous predictions, high severity, or threat indicators
        threat_events = [
            e for e in events
            if str(e.get("m2_prediction", "")).lower() == "anomalous"
            or str(e.get("severity", "")).lower() in ["critical", "high"]
            or bool(e.get("threat_indicator", False))
            or bool(e.get("threat_match", False))
        ]

        # Use 30-minute correlation window
        clusters = EventCorrelationEngine.correlate_events(threat_events, window_minutes=30)
        
        # Also include non-cluster high-threat anchor events if needed
        all_clusters = clusters if clusters else [[e] for e in threat_events[:50]]

        created_count = 0
        for idx, cluster in enumerate(all_clusters, start=1):
            inc_id = f"INC-{idx:03d}"
            scenario_title, stages = EventCorrelationEngine.identify_attack_chain_scenario(cluster)

            # Extract dominant attributes across cluster
            primary_asset = cluster[0].get("asset_name") or "Unknown Asset"
            primary_user = cluster[0].get("username") or "Unknown User"

            # Max severity & confidence across cluster
            severities = [c.get("severity") or c.get("m2_severity") or "Low" for c in cluster]
            sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            highest_sev = max(severities, key=lambda s: sev_rank.get(str(s).capitalize(), 1))

            confidences = [float(c.get("confidence_score") or 50.0) for c in cluster]
            max_conf = max(confidences) if confidences else 50.0

            # Check if any event in cluster matched a known CVE or threat feed
            cvss_scores = [float(c.get("cvss_score") or 0.0) for c in cluster]
            max_cvss = max(cvss_scores) if cvss_scores else 0.0
            matching_vuln = next((c.get("vulnerability_id") for c in cluster if c.get("vulnerability_id") not in ["No Vulnerability", "None", None]), "")

            threat_matched = any(bool(c.get("threat_match", False)) or bool(c.get("malicious_ip_flag", 0) == 1) for c in cluster)
            threat_indicator = any(bool(c.get("threat_indicator", False)) for c in cluster)
            feed_severity = next((c.get("threat_severity") for c in cluster if c.get("threat_severity") not in ["None", "Unknown", None]), "None")
            threat_name = next((c.get("threat_name") for c in cluster if c.get("threat_name") not in ["No Match", "Unknown", None]), "")

            # Mitre technique from first stage
            mitre_id = stages[0].get("mitre_id", "T1000") if stages else "T1000"

            # Calculate composite risk score
            risk_calc = RiskScoreEngine.calculate_risk(
                threat_severity_input=highest_sev,
                ml_confidence=max_conf,
                asset_name=primary_asset,
                cvss_score=max_cvss,
                vulnerability_id=matching_vuln,
                threat_match=threat_matched,
                threat_indicator=threat_indicator,
                threat_severity_feed=feed_severity,
                threat_name=threat_name,
                related_events_count=len(cluster)
            )

            # Generate response recommendations
            recommendations = RecommendationEngine.get_recommendations(
                threat_type=scenario_title,
                priority=risk_calc["priority"],
                threat_severity=highest_sev
            )

            earliest_time = cluster[0].get("timestamp", "")
            event_ids = [c.get("event_id") for c in cluster]

            incident_record = {
                "incident_id": inc_id,
                "event_ids": event_ids,
                "threat_type": scenario_title,
                "risk_score": risk_calc["risk_score"],
                "priority": risk_calc["priority"],
                "asset_id": primary_asset,
                "department": cluster[0].get("department") or "IT",
                "affected_user": primary_user,
                "mitre_technique": mitre_id,
                "status": "Open" if idx % 5 != 0 else "Investigating",
                "recommendation": recommendations,
                "risk_factors": risk_calc["factors"],
                "explainability": risk_calc["explainability"],
                "attack_chain": stages,
                "created_at": earliest_time,
                "status_history": [
                    {
                        "from_status": "Initial",
                        "to_status": "Open" if idx % 5 != 0 else "Investigating",
                        "changed_at": earliest_time,
                        "analyst": "Automated Correlation Engine",
                        "notes": "Incident correlated from anomalous threat cluster"
                    }
                ],
                "status_updated_at": earliest_time
            }

            IncidentRepository.save_incident(incident_record)
            created_count += 1

        print(f"[IncidentService] Successfully persisted {created_count} correlated security incidents.")
        return created_count

    @classmethod
    def get_incidents(cls,
                      priority: Optional[str] = None,
                      threat_type: Optional[str] = None,
                      asset_id: Optional[str] = None,
                      department: Optional[str] = None,
                      mitre_technique: Optional[str] = None,
                      ioc_status: Optional[str] = None,
                      status: Optional[str] = None,
                      search: Optional[str] = None,
                      date_from: Optional[str] = None,
                      date_to: Optional[str] = None,
                      sort_by: str = "risk_score",
                      sort_order: str = "desc",
                      page: int = 1,
                      limit: int = 25) -> Dict[str, Any]:
        """Retrieves prioritized and filtered incidents with multi-criteria support."""
        raw_data = IncidentRepository.get_incidents(
            priority=priority,
            threat_type=threat_type,
            asset_id=asset_id,
            department=department,
            mitre_technique=mitre_technique,
            ioc_status=ioc_status,
            status=status,
            search=search,
            date_from=date_from,
            date_to=date_to,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            limit=limit
        )
        ranked_incidents = ThreatPrioritization.rank_incidents(raw_data.get("incidents", []))
        for inc_item in ranked_incidents:
            cls._enrich_incident_aliases(inc_item)
        return {
            "total": raw_data.get("total", 0),
            "page": page,
            "limit": limit,
            "incidents": ranked_incidents
        }

    @classmethod
    def _enrich_incident_aliases(cls, inc_dict: Dict[str, Any], detailed_events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Adds backward-compatible aliases according to M3 specification without removing existing fields."""
        # Fix 1 aliases: preserve existing asset_id, priority, explainability, recommendation, event_ids
        inc_dict["affected_asset"] = inc_dict.get("asset_id")
        inc_dict["risk_level"] = inc_dict.get("priority")
        inc_dict["reasons"] = inc_dict.get("explainability", [])
        inc_dict["recommendations"] = inc_dict.get("recommendation", [])

        # Related events information: expose related_events while preserving event_ids and detailed_events
        if detailed_events is not None:
            inc_dict["related_events"] = detailed_events
        elif "related_events" not in inc_dict:
            inc_dict["related_events"] = inc_dict.get("event_ids", [])

        # Additive top-level ML confidence and MITRE aliases if available
        if "ml_confidence" not in inc_dict:
            inc_dict["ml_confidence"] = inc_dict.get("risk_factors", {}).get("ml_confidence", {}).get("raw", 0.0)
        if "mitre_techniques" not in inc_dict and inc_dict.get("mitre_technique"):
            inc_dict["mitre_techniques"] = [inc_dict.get("mitre_technique")]

        return inc_dict

    @classmethod
    def get_incident_by_id(cls, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves complete incident details including contributing events and specification aliases."""
        inc = IncidentRepository.get_incident_by_id(incident_id)
        if not inc:
            return None

        # Fetch underlying security event details
        detailed_events = []
        for evt_id in inc.get("event_ids", []):
            evt = PredictionRepository.get_event_with_prediction(evt_id)
            if evt:
                detailed_events.append(evt)

        inc_copy = dict(inc)
        inc_copy["detailed_events"] = detailed_events
        cls._enrich_incident_aliases(inc_copy, detailed_events=detailed_events)
        return inc_copy

    @classmethod
    def get_incident_risk_comparison(cls, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Computes comparative risk analysis: isolated single-event base score vs.
        correlated composite score, delta calculation, and data-backed explanation.
        """
        inc = IncidentRepository.get_incident_by_id(incident_id)
        if not inc:
            return None

        event_ids = inc.get("event_ids", [])
        primary_event = None
        if event_ids:
            primary_event = PredictionRepository.get_event_with_prediction(event_ids[0])

        if primary_event:
            isolated_calc = RiskScoreEngine.calculate_isolated_event_risk(primary_event)
        else:
            isolated_calc = {
                "risk_score": max(0, inc.get("risk_score", 50) - 5),
                "priority": inc.get("priority", "Low"),
                "factors": inc.get("risk_factors", {})
            }

        correlated_score = inc.get("risk_score", 0)
        isolated_score = isolated_calc["risk_score"]
        stages = inc.get("attack_chain", [])
        delta_info = RiskScoreEngine.explain_correlation_delta(
            isolated_score=isolated_score,
            correlated_score=correlated_score,
            event_count=len(event_ids) or 1,
            unique_types=len(set(s.get("event_type", "") for s in stages)) or 1,
            stages_count=len(stages) or 1
        )

        return {
            "incident_id": incident_id,
            "threat_type": inc.get("threat_type"),
            "isolated_score": isolated_score,
            "isolated_priority": isolated_calc.get("priority"),
            "isolated_factors": isolated_calc.get("factors"),
            "correlated_score": correlated_score,
            "correlated_priority": inc.get("priority"),
            "correlated_factors": inc.get("risk_factors"),
            "delta": delta_info["delta"],
            "delta_label": delta_info["delta_label"],
            "is_elevated": delta_info["is_elevated"],
            "reasons": delta_info["reasons"],
            "contributing_events_count": len(event_ids),
            "stages_count": len(stages)
        }

    @classmethod
    def get_incident_timeline(cls, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Compiles complete chronological timeline for an incident:
        1. Underlying security events with ML anomaly classifications
        2. Attack chain stages and MITRE tactics
        3. Analyst investigation status updates & notes
        4. Analyst feedback
        """
        inc = cls.get_incident_by_id(incident_id)
        if not inc:
            return None

        timeline_entries = []

        # 1. Contributing security events
        for evt in inc.get("detailed_events", []):
            timeline_entries.append({
                "type": "security_event",
                "timestamp": evt.get("timestamp", ""),
                "title": f"Security Event: {evt.get('event_type') or 'Detection'}",
                "description": f"Target: {evt.get('asset_name')} | Source: {evt.get('source_ip')} | Prediction: {evt.get('m2_prediction', 'Anomalous')} ({evt.get('confidence_score', 0):.1f}%)",
                "severity": evt.get("severity") or evt.get("m2_severity") or "Low",
                "badge": evt.get("m2_prediction") or "Event",
                "details": {
                    "event_id": evt.get("event_id"),
                    "source_ip": evt.get("source_ip"),
                    "destination_ip": evt.get("destination_ip"),
                    "cvss_score": evt.get("cvss_score"),
                    "vulnerability_id": evt.get("vulnerability_id")
                }
            })

        # 2. Attack chain stages
        for stage in inc.get("attack_chain", []):
            timeline_entries.append({
                "type": "attack_chain_stage",
                "timestamp": stage.get("timestamp", ""),
                "title": f"Attack Stage: {stage.get('stage')} ({stage.get('mitre_id')})",
                "description": f"{stage.get('technique_name')} • Event: {stage.get('event_type')}",
                "severity": inc.get("priority", "Medium"),
                "badge": stage.get("stage", "Kill Chain"),
                "details": stage
            })

        # 3. Status history entries
        for hist in inc.get("status_history", []):
            timeline_entries.append({
                "type": "status_change",
                "timestamp": hist.get("changed_at", ""),
                "title": f"Status Changed: {hist.get('from_status')} -> {hist.get('to_status')}",
                "description": f"Updated by {hist.get('analyst', 'Analyst')}: {hist.get('notes') or 'No additional notes'}",
                "severity": "Info",
                "badge": hist.get("to_status"),
                "details": hist
            })

        # 4. Analyst feedback if present
        if inc.get("analyst_feedback") and inc.get("analyst_feedback") != "Unassigned":
            timeline_entries.append({
                "type": "analyst_feedback",
                "timestamp": inc.get("feedback_timestamp", ""),
                "title": f"Analyst Review: {inc.get('analyst_feedback')}",
                "description": f"Reviewer: {inc.get('feedback_analyst') or 'Analyst'} | Notes: {inc.get('feedback_notes') or 'N/A'}",
                "severity": "Info",
                "badge": inc.get("analyst_feedback"),
                "details": {
                    "feedback": inc.get("analyst_feedback"),
                    "notes": inc.get("feedback_notes"),
                    "analyst": inc.get("feedback_analyst")
                }
            })

        # Sort timeline chronologically (earliest to latest)
        timeline_entries.sort(key=lambda x: str(x.get("timestamp", "")))

        return {
            "incident_id": incident_id,
            "threat_type": inc.get("threat_type"),
            "priority": inc.get("priority"),
            "current_status": inc.get("status"),
            "analyst_feedback": inc.get("analyst_feedback"),
            "total_timeline_events": len(timeline_entries),
            "timeline": timeline_entries
        }

    @classmethod
    def get_attack_chains(cls) -> List[Dict[str, Any]]:
        """Retrieves all detected multi-stage attack chains across incidents with specification aliases."""
        data = IncidentRepository.get_incidents(limit=0)
        chains = []
        for inc in data.get("incidents", []):
            stages = inc.get("attack_chain") or []
            if stages and len(stages) >= 2:
                # Extract unique MITRE techniques represented inside stages
                techniques = []
                for s in stages:
                    m_id = s.get("mitre_id")
                    if m_id and m_id not in ["Unknown", None] and m_id not in techniques:
                        techniques.append(m_id)

                event_ids = inc.get("event_ids") or [s.get("event_id") for s in stages if s.get("event_id")]

                chain_entry = {
                    # Fix 2 specification-compatible aliases
                    "attack_chain_id": inc.get("incident_id"),
                    "events": event_ids,
                    "event_ids": event_ids,
                    "techniques": techniques,
                    "stage": stages[-1].get("stage", "Unknown") if stages else "Unknown",

                    # Preserved existing fields
                    "incident_id": inc.get("incident_id"),
                    "threat_type": inc.get("threat_type"),
                    "risk_score": inc.get("risk_score"),
                    "priority": inc.get("priority"),
                    "risk_level": inc.get("priority"),
                    "asset_id": inc.get("asset_id"),
                    "affected_asset": inc.get("asset_id"),
                    "affected_user": inc.get("affected_user"),
                    "stages_count": len(stages),
                    "stages": stages,
                    "created_at": inc.get("created_at")
                }

                # Confidence: genuinely available from M2 prediction within risk_factors
                ml_conf = inc.get("risk_factors", {}).get("ml_confidence", {}).get("raw")
                if ml_conf is not None:
                    chain_entry["confidence"] = ml_conf

                chains.append(chain_entry)
        return chains

    @classmethod
    def get_recommendations_for_incident(cls, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves guidance recommendations for a specific incident."""
        inc = IncidentRepository.get_incident_by_id(incident_id)
        if not inc:
            return None
        return {
            "incident_id": incident_id,
            "threat_type": inc.get("threat_type"),
            "risk_score": inc.get("risk_score"),
            "priority": inc.get("priority"),
            "risk_level": inc.get("priority"),
            "recommendation": inc.get("recommendation", []),
            "recommendations": inc.get("recommendation", [])
        }

    @classmethod
    def update_incident_status(cls, incident_id: str, new_status: str, analyst: str = "SOC Analyst", notes: str = "") -> bool:
        """Updates analyst investigation status of an incident with audit logging."""
        return IncidentRepository.update_incident_status(incident_id, new_status, analyst=analyst, notes=notes)

    @classmethod
    def add_analyst_feedback(cls, incident_id: str, feedback: str, notes: str = "", analyst: str = "SOC Analyst") -> bool:
        """Saves analyst review feedback (True Positive, False Positive, Needs Review)."""
        return IncidentRepository.save_analyst_feedback(incident_id, feedback, notes=notes, analyst=analyst)

    @classmethod
    def recalculate_all_incidents(cls, weights: Dict[str, float] = None) -> Dict[str, Any]:
        """
        Recalculates risk scores and factors for all persisted incidents using active or custom weights.
        Returns the number of updated incidents and the new average risk score.
        """
        w = weights or RiskScoreEngine.get_active_weights()
        raw = IncidentRepository.get_incidents(limit=0)
        incidents = raw.get("incidents", [])
        if not incidents:
            return {"updated_count": 0, "average_risk_score": 0.0}

        updated_count = 0
        total_score = 0
        for inc in incidents:
            event_ids = inc.get("event_ids", [])
            cluster = []
            for eid in event_ids:
                evt = PredictionRepository.get_event_with_prediction(eid)
                if evt:
                    cluster.append(evt)

            if cluster:
                severities = [c.get("severity") or c.get("m2_severity") or "Low" for c in cluster]
                sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
                highest_sev = max(severities, key=lambda s: sev_rank.get(str(s).capitalize(), 1))
                confidences = [float(c.get("confidence_score") or 50.0) for c in cluster]
                max_conf = max(confidences) if confidences else 50.0
                cvss_scores = [float(c.get("cvss_score") or 0.0) for c in cluster]
                max_cvss = max(cvss_scores) if cvss_scores else 0.0
                matching_vuln = next((c.get("vulnerability_id") for c in cluster if c.get("vulnerability_id") not in ["No Vulnerability", "None", None]), "")
                threat_matched = any(bool(c.get("threat_match", False)) or bool(c.get("malicious_ip_flag", 0) == 1) for c in cluster)
                threat_indicator = any(bool(c.get("threat_indicator", False)) for c in cluster)
                feed_severity = next((c.get("threat_severity") for c in cluster if c.get("threat_severity") not in ["None", "Unknown", None]), "None")
                threat_name = next((c.get("threat_name") for c in cluster if c.get("threat_name") not in ["No Match", "Unknown", None]), "")

                risk_calc = RiskScoreEngine.calculate_risk(
                    threat_severity_input=highest_sev,
                    ml_confidence=max_conf,
                    asset_name=inc.get("asset_id", ""),
                    cvss_score=max_cvss,
                    vulnerability_id=matching_vuln,
                    threat_match=threat_matched,
                    threat_indicator=threat_indicator,
                    threat_severity_feed=feed_severity,
                    threat_name=threat_name,
                    weights=w,
                    related_events_count=len(cluster)
                )

                inc["risk_score"] = risk_calc["risk_score"]
                inc["priority"] = risk_calc["priority"]
                inc["risk_factors"] = risk_calc["factors"]
                inc["explainability"] = risk_calc["explainability"]
                IncidentRepository.save_incident(inc)
                updated_count += 1
                total_score += risk_calc["risk_score"]

        avg = round(total_score / updated_count, 1) if updated_count > 0 else 0.0
        return {"updated_count": updated_count, "average_risk_score": avg}

