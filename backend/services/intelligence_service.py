"""
Threat Intelligence Service for Milestone 3 (`backend/services/intelligence_service.py`).
Provides endpoints and lookups for MITRE ATT&CK taxonomy mappings, active IOC feeds,
and asset criticality configurations.
"""
import os
import sys
from typing import Dict, Any, List

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.risk.correlation import EVENT_TACTIC_MAP, MITRE_TACTIC_ORDER
from backend.risk.risk_score import KNOWN_ASSET_CRITICALITY, CRITICALITY_LEVEL_MAP

class IntelligenceService:
    """Provides threat intelligence, IOC, MITRE context, and asset criticality data."""

    @staticmethod
    def get_mitre_taxonomy() -> Dict[str, Any]:
        """Retrieves MITRE ATT&CK framework tactics and technique mappings used in M3."""
        mappings = []
        for evt_type, (tactic, tid, tname) in EVENT_TACTIC_MAP.items():
            mappings.append({
                "event_type": evt_type.title(),
                "tactic": tactic,
                "technique_id": tid,
                "technique_name": tname
            })

        return {
            "tactics_kill_chain": MITRE_TACTIC_ORDER,
            "mapped_event_types": len(mappings),
            "techniques": mappings
        }

    @staticmethod
    def get_asset_criticality_table() -> List[Dict[str, Any]]:
        """Retrieves asset criticality classifications and normalized weighting values."""
        assets = []
        for name, level in KNOWN_ASSET_CRITICALITY.items():
            mult = CRITICALITY_LEVEL_MAP.get(level, 0.25)
            assets.append({
                "asset_name": name.title(),
                "criticality_level": level.capitalize(),
                "normalized_multiplier": mult,
                "weight_score": int(mult * 100)
            })
        return assets

    @classmethod
    def get_intelligence_overview(cls) -> Dict[str, Any]:
        """
        Aggregates real security intelligence across 4 core quadrants from genuine M1/M2/M3 records:
        1. Threat Intelligence (IOCs, Threat Feeds, Malicious Matches, Threat Actors)
        2. Vulnerability Intelligence (CVEs, CVSS ratings, Patch status)
        3. MITRE ATT&CK Intelligence (Tactics distribution, Active techniques, Kill-chain coverage)
        4. Asset Intelligence (Asset criticality, Department exposure, Most targeted systems)
        """
        from backend.database.prediction_repository import PredictionRepository
        from backend.database.incident_repository import IncidentRepository

        events = PredictionRepository.get_all_events_for_correlation()
        incidents_data = IncidentRepository.get_incidents(limit=0)
        incidents = incidents_data.get("incidents", [])

        # 1. Threat Intel Metrics
        threat_iocs = []
        feed_sev_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        indicator_types = {}
        threat_actors = {}
        seen_iocs = set()

        # 2. Vulnerability Intel Metrics
        cve_map = {}
        cvss_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        patch_status_counts = {"Patched": 0, "Unpatched": 0, "Patch Available": 0, "No Patch": 0}
        total_vuln_events = 0
        total_cvss_sum = 0.0

        # 3. MITRE ATT&CK Metrics
        tactic_counts = {}
        technique_counts = {}

        # 4. Asset Intel Metrics
        asset_event_counts = {}
        dept_counts = {}
        asset_info_map = {}

        for e in events:
            # Threat Intel
            is_ioc = bool(e.get("threat_indicator")) or bool(e.get("threat_match")) or int(e.get("malicious_ip_flag") or 0) == 1
            if is_ioc:
                t_name = e.get("threat_name") or "Suspicious Indicator"
                t_actor = e.get("threat_actor") or "Unknown"
                t_type = e.get("indicator_type") or "IP Address"
                t_sev = (e.get("threat_severity") or "Medium").capitalize()
                if t_sev not in feed_sev_dist:
                    t_sev = "Medium"
                feed_sev_dist[t_sev] += 1
                indicator_types[t_type] = indicator_types.get(t_type, 0) + 1

                if t_actor and t_actor != "Unknown":
                    threat_actors[t_actor] = threat_actors.get(t_actor, 0) + 1

                ioc_key = (e.get("source_ip"), t_name)
                if ioc_key not in seen_iocs and len(threat_iocs) < 15:
                    seen_iocs.add(ioc_key)
                    threat_iocs.append({
                        "ioc_value": e.get("source_ip") or "0.0.0.0",
                        "indicator_type": t_type,
                        "threat_name": t_name,
                        "threat_actor": t_actor,
                        "severity": t_sev,
                        "confidence": e.get("confidence") or "High",
                        "last_seen": e.get("timestamp", "")
                    })

            # Vulnerability Intel
            v_id = e.get("vulnerability_id")
            if v_id and v_id not in ["No Vulnerability", "None", "", None]:
                total_vuln_events += 1
                cvss = float(e.get("cvss_score") or 0.0)
                total_cvss_sum += cvss
                if cvss >= 9.0:
                    cvss_dist["Critical"] += 1
                elif cvss >= 7.0:
                    cvss_dist["High"] += 1
                elif cvss >= 4.0:
                    cvss_dist["Medium"] += 1
                else:
                    cvss_dist["Low"] += 1

                patch_avail = str(e.get("patch_available") or "").strip().lower()
                if patch_avail in ["yes", "true", "available"]:
                    patch_status_counts["Patch Available"] += 1
                elif patch_avail in ["no", "false"]:
                    patch_status_counts["No Patch"] += 1
                elif patch_avail in ["patched", "closed"]:
                    patch_status_counts["Patched"] += 1
                else:
                    patch_status_counts["Unpatched"] += 1

                if v_id not in cve_map:
                    cve_map[v_id] = {
                        "vulnerability_id": v_id,
                        "vulnerability_name": e.get("vulnerability_name") or v_id,
                        "cvss_score": cvss,
                        "patch_available": e.get("patch_available") or "Unknown",
                        "affected_assets": set(),
                        "occurrences": 0
                    }
                cve_map[v_id]["occurrences"] += 1
                if e.get("asset_name"):
                    cve_map[v_id]["affected_assets"].add(e.get("asset_name"))

            # MITRE Intel
            tac = e.get("tactic")
            if tac and tac not in ["Unknown", None]:
                tactic_counts[tac] = tactic_counts.get(tac, 0) + 1
            m_id = e.get("mitre_id")
            if m_id and m_id not in ["Unknown", None]:
                t_name = e.get("technique_name") or m_id
                key = (m_id, t_name, tac or "Execution")
                technique_counts[key] = technique_counts.get(key, 0) + 1

            # Asset Intel
            a_name = e.get("asset_name") or "Unknown"
            if a_name != "Unknown":
                asset_event_counts[a_name] = asset_event_counts.get(a_name, 0) + 1
                dept = e.get("department") or "IT"
                dept_counts[dept] = dept_counts.get(dept, 0) + 1
                if a_name not in asset_info_map:
                    crit = e.get("criticality") or "Medium"
                    asset_info_map[a_name] = {
                        "asset_name": a_name,
                        "department": dept,
                        "criticality": crit.capitalize(),
                        "owner": e.get("owner") or "SecOps Team",
                        "asset_type": e.get("asset_type") or "Server"
                    }

        # Format Top CVEs
        top_cves = []
        for cve in sorted(cve_map.values(), key=lambda x: (x["cvss_score"], x["occurrences"]), reverse=True)[:10]:
            top_cves.append({
                "vulnerability_id": cve["vulnerability_id"],
                "vulnerability_name": cve["vulnerability_name"],
                "cvss_score": cve["cvss_score"],
                "patch_available": cve["patch_available"],
                "affected_assets_count": len(cve["affected_assets"]),
                "occurrences": cve["occurrences"]
            })

        # Format Top MITRE Techniques
        top_techniques = []
        for (m_id, t_name, tac), count in sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            top_techniques.append({
                "mitre_id": m_id,
                "technique_name": t_name,
                "tactic": tac,
                "occurrences": count
            })

        # Asset incidents mapping
        asset_incident_counts = {}
        for inc in incidents:
            a_id = inc.get("asset_id")
            if a_id:
                asset_incident_counts[a_id] = asset_incident_counts.get(a_id, 0) + 1

        top_assets = []
        for a_name, evt_cnt in sorted(asset_event_counts.items(), key=lambda x: (asset_incident_counts.get(x[0], 0), x[1]), reverse=True)[:10]:
            info = asset_info_map.get(a_name, {})
            top_assets.append({
                "asset_name": a_name,
                "department": info.get("department", "IT"),
                "criticality": info.get("criticality", "Medium"),
                "owner": info.get("owner", "SecOps Team"),
                "asset_type": info.get("asset_type", "Server"),
                "event_count": evt_cnt,
                "incident_count": asset_incident_counts.get(a_name, 0)
            })

        crit_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for info in asset_info_map.values():
            c = info.get("criticality", "Medium")
            crit_dist[c] = crit_dist.get(c, 0) + 1

        avg_cvss = round(total_cvss_sum / total_vuln_events, 2) if total_vuln_events > 0 else 0.0

        return {
            "threat_intelligence": {
                "total_threat_indicators": sum(feed_sev_dist.values()),
                "feed_severity_distribution": feed_sev_dist,
                "indicator_types": indicator_types,
                "top_threat_actors": [{"actor": k, "count": v} for k, v in sorted(threat_actors.items(), key=lambda x: x[1], reverse=True)[:6]],
                "active_iocs": threat_iocs
            },
            "vulnerability_intelligence": {
                "total_cves_tracked": len(cve_map),
                "total_vulnerable_events": total_vuln_events,
                "average_cvss_score": avg_cvss,
                "cvss_severity_distribution": cvss_dist,
                "patch_status_breakdown": patch_status_counts,
                "top_vulnerabilities": top_cves
            },
            "mitre_intelligence": {
                "total_tactics_observed": len(tactic_counts),
                "total_techniques_mapped": len(technique_counts),
                "tactics_distribution": tactic_counts,
                "tactics_kill_chain": MITRE_TACTIC_ORDER,
                "top_techniques": top_techniques
            },
            "asset_intelligence": {
                "total_managed_assets": len(asset_info_map),
                "criticality_distribution": crit_dist,
                "department_distribution": dept_counts,
                "most_targeted_assets": top_assets
            }
        }
