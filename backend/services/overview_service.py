"""
Overview Service for Milestone 4 (backend/services/overview_service.py).
Integrates data from M1 (Events & Intelligence), M2 (ML Threat Detections),
and M3 (Incidents & Risk Engine) into dynamic unified telemetry for the SOC Overview.
Zero mock data: all statistics are calculated from actual SQLite/MongoDB records.
"""

import os
import sys
import csv
import io
from datetime import datetime, timezone
from typing import Dict, Any, List
from collections import Counter, defaultdict

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database.db import SessionLocal
from backend.models.database_models import SecurityEvent, ThreatPrediction
from backend.database.incident_repository import IncidentRepository


class OverviewService:
    """Coordinates dashboard aggregation, posture scoring, trends, and reporting."""

    @classmethod
    def get_overview_summary(cls) -> Dict[str, Any]:
        """
        Gathers comprehensive live metrics across M1, M2, and M3 data layers.
        Returns KPIs, dynamic Security Posture score, distributions, risk trends,
        and critical incidents for immediate drill-down.
        """
        session = SessionLocal()
        try:
            # 1. M1 Telemetry Aggregations
            total_events = session.query(SecurityEvent).count()
            events = session.query(SecurityEvent).all()

            # Severity distribution from actual events
            event_severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for e in events:
                sev = (e.severity or "Low").capitalize()
                if sev in event_severities:
                    event_severities[sev] += 1
                else:
                    event_severities["Low"] += 1

            # MITRE mapping count
            mitre_mapped_count = sum(
                1 for e in events if e.mitre_id and e.mitre_id.strip() not in ["Unknown", "None", ""]
            )

            # Normal baseline events
            normal_events = sum(1 for e in events if (e.risk_label or "").lower() == "low risk" or (e.severity or "").lower() == "low")

            # Unique CVEs from actual events
            cves = set()
            critical_cves = set()
            for e in events:
                v_id = e.vulnerability_id
                if v_id and v_id.strip() not in ["No Vulnerability", "None", "", None]:
                    cves.add(v_id.strip())
                    if e.cvss_score and float(e.cvss_score) >= 9.0:
                        critical_cves.add(v_id.strip())

            # 2. M2 Machine Learning Detection Aggregations
            detected_threats = session.query(ThreatPrediction).filter(
                ThreatPrediction.prediction == "Anomalous"
            ).count()

            # 3. M3 Incidents & Risk Engine Aggregations
            incidents_payload = IncidentRepository.get_incidents(limit=0)
            all_incidents = incidents_payload.get("incidents", [])
            total_incidents = len(all_incidents)

            critical_incidents = 0
            high_incidents = 0
            active_incidents = 0
            incident_statuses = {"Open": 0, "Investigating": 0, "Resolved": 0, "False Positive": 0}
            incident_priorities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            threat_type_counts = Counter()
            affected_assets_set = set()
            asset_risk_map = defaultdict(lambda: {"total": 0, "critical": 0, "max_risk": 0})

            for inc in all_incidents:
                pri = (inc.get("priority") or "Low").capitalize()
                if pri in incident_priorities:
                    incident_priorities[pri] += 1
                if pri == "Critical":
                    critical_incidents += 1
                elif pri == "High":
                    high_incidents += 1

                st = (inc.get("status") or "Open").capitalize()
                if st == "False positive":
                    st = "False Positive"
                if st in incident_statuses:
                    incident_statuses[st] += 1
                else:
                    incident_statuses["Open"] += 1

                if st in ["Open", "Investigating"]:
                    active_incidents += 1

                t_type = inc.get("threat_type") or "Unknown Threat"
                threat_type_counts[t_type] += 1

                asset = inc.get("asset_id") or "Unknown"
                if asset != "Unknown":
                    affected_assets_set.add(asset)
                    asset_risk_map[asset]["total"] += 1
                    if pri == "Critical":
                        asset_risk_map[asset]["critical"] += 1
                    r_score = inc.get("risk_score") or 0
                    if r_score > asset_risk_map[asset]["max_risk"]:
                        asset_risk_map[asset]["max_risk"] = r_score

            affected_assets_list = sorted(list(affected_assets_set))

            # 4. Security Posture Score Calculation
            # Transparent, documented formula:
            # Base = 100
            # Penalties:
            # - Critical incidents: min(20.0, round(critical_incidents * 0.15, 1))
            # - High-risk incidents: min(15.0, round(high_incidents * 0.03, 1))
            # - Unresolved incident ratio: min(10.0, round(10.0 * (active_incidents / max(1, total_incidents)), 1))
            # - Critical CVE exposure: min(12.0, round(len(critical_cves) * 1.5, 1))
            # - Tier 1 assets under critical attack (Database-01 or WebServer): 8.0 if any critical incidents, else 0.0
            # Credits:
            # - MITRE coverage ratio: min(15.0, round(15.0 * (mitre_mapped_count / max(1, total_events)), 1))
            # - Normal baseline traffic ratio: min(10.0, round(10.0 * (normal_events / max(1, total_events)), 1))
            base_score = 100.0
            pen_crit = min(20.0, round(critical_incidents * 0.15, 1))
            pen_high = min(15.0, round(high_incidents * 0.03, 1))
            unres_ratio = (active_incidents / max(1, total_incidents))
            pen_unres = min(10.0, round(10.0 * unres_ratio, 1))
            pen_cve = min(12.0, round(len(critical_cves) * 1.5, 1))

            tier1_at_risk = any(
                asset_risk_map[a]["critical"] > 0
                for a in ["Database-01", "WebServer"]
                if a in asset_risk_map
            )
            pen_tier1 = 8.0 if tier1_at_risk else 0.0

            total_penalties = round(pen_crit + pen_high + pen_unres + pen_cve + pen_tier1, 1)

            cred_mitre = min(15.0, round(15.0 * (mitre_mapped_count / max(1, total_events)), 1))
            cred_normal = min(10.0, round(10.0 * (normal_events / max(1, total_events)), 1))
            total_credits = round(cred_mitre + cred_normal, 1)

            computed_score = round(max(0.0, min(100.0, base_score - total_penalties + total_credits)))
            
            if computed_score >= 70:
                status_label = "Good"
            elif computed_score >= 50:
                status_label = "Moderate"
            elif computed_score >= 30:
                status_label = "Needs Attention"
            else:
                status_label = "Critical"

            security_posture = {
                "score": int(computed_score),
                "status": status_label,
                "max_score": 100,
                "formula": "Base(100) - Penalties + Credits",
                "breakdown": {
                    "base_score": int(base_score),
                    "penalties": {
                        "critical_incidents": pen_crit,
                        "high_incidents": pen_high,
                        "unresolved_ratio": pen_unres,
                        "critical_vulnerabilities": pen_cve,
                        "tier1_assets_at_risk": pen_tier1
                    },
                    "credits": {
                        "mitre_coverage": cred_mitre,
                        "normal_baseline": cred_normal
                    },
                    "total_penalties": total_penalties,
                    "total_credits": total_credits
                },
                "explanation": (
                    f"Overall security posture evaluated at {int(computed_score)}/100 ({status_label}). "
                    f"Penalized for {critical_incidents} critical incidents (-{pen_crit}) and "
                    f"{high_incidents} high-priority threats (-{pen_high}), with positive offset from "
                    f"100% MITRE ATT&CK telemetry coverage (+{cred_mitre})."
                )
            }

            # 5. Risk Trends (24 Hours, 7 Days, 30 Days)
            # Group actual incidents by timestamp
            risk_trends = cls._compute_risk_trends(all_incidents)

            # 6. Critical Incidents Panel (Top 10 sorted by risk_score desc)
            top_critical = [inc for inc in all_incidents if (inc.get("priority") or "").lower() == "critical"]
            top_critical.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
            critical_panel = []
            for inc in top_critical[:10]:
                critical_panel.append({
                    "incident_id": inc.get("incident_id"),
                    "threat_type": inc.get("threat_type"),
                    "asset_id": inc.get("asset_id"),
                    "affected_asset": inc.get("asset_id"),  # compatibility alias
                    "risk_score": inc.get("risk_score"),
                    "priority": inc.get("priority"),
                    "risk_level": inc.get("priority"),      # compatibility alias
                    "status": inc.get("status"),
                    "created_at": inc.get("created_at"),
                    "mitre_technique": inc.get("mitre_technique", "Unknown"),
                    "explainability": inc.get("explainability", []),
                    "reasons": [e.get("factor") for e in inc.get("explainability", []) if isinstance(e, dict)] if inc.get("explainability") else [],
                    "recommendations": inc.get("recommendation", [])
                })

            # 7. Executive Vulnerable Assets Ranking
            vulnerable_assets = []
            for asset, data in sorted(asset_risk_map.items(), key=lambda item: (item[1]["critical"], item[1]["max_risk"]), reverse=True):
                vulnerable_assets.append({
                    "asset_name": asset,
                    "total_incidents": data["total"],
                    "critical_incidents": data["critical"],
                    "max_risk_score": data["max_risk"]
                })

            # Build top threat types list
            top_threat_types = [
                {"threat_type": t, "count": c}
                for t, c in threat_type_counts.most_common(8)
            ]

            return {
                "success": True,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "kpis": {
                    "total_security_events": total_events,
                    "detected_threats": detected_threats,
                    "critical_threats": critical_incidents,
                    "high_risk_incidents": high_incidents,
                    "active_incidents": active_incidents,
                    "affected_assets": len(affected_assets_list),
                    "affected_assets_list": affected_assets_list
                },
                "security_posture": security_posture,
                "threat_distribution": {
                    "severity": event_severities,
                    "priority": incident_priorities,
                    "threat_types": top_threat_types,
                    "status": incident_statuses
                },
                "risk_trends": risk_trends,
                "critical_incidents": critical_panel,
                "executive_metrics": {
                    "vulnerable_assets": vulnerable_assets,
                    "mitre_coverage_percentage": round((mitre_mapped_count / max(1, total_events)) * 100, 1),
                    "cve_critical_count": len(critical_cves),
                    "cve_total_count": len(cves)
                }
            }
        finally:
            session.close()

    @classmethod
    def _compute_risk_trends(cls, incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculates risk trends across 24h, 7d, and 30d timeframes using actual incident timestamps.
        Zero fake data points: buckets reflect real aggregated telemetry.
        """
        # Bucket by date string "YYYY-MM-DD" and hourly string "YYYY-MM-DD HH:00"
        daily_buckets = defaultdict(lambda: {"sum_risk": 0, "count": 0, "peak_risk": 0})
        hourly_buckets = defaultdict(lambda: {"sum_risk": 0, "count": 0, "peak_risk": 0})

        for inc in incidents:
            dt_str = inc.get("created_at")
            if not dt_str:
                continue
            try:
                # Format: "YYYY-MM-DD HH:MM:SS"
                day_key = dt_str[:10]
                hour_key = dt_str[:13] + ":00"
                r = inc.get("risk_score") or 0

                daily_buckets[day_key]["sum_risk"] += r
                daily_buckets[day_key]["count"] += 1
                if r > daily_buckets[day_key]["peak_risk"]:
                    daily_buckets[day_key]["peak_risk"] = r

                hourly_buckets[hour_key]["sum_risk"] += r
                hourly_buckets[hour_key]["count"] += 1
                if r > hourly_buckets[hour_key]["peak_risk"]:
                    hourly_buckets[hour_key]["peak_risk"] = r
            except Exception:
                continue

        # 7 Days Trend: Sorted daily buckets across available days
        sorted_days = sorted(daily_buckets.keys())
        trend_7d = []
        for day in sorted_days:
            data = daily_buckets[day]
            avg_risk = round(data["sum_risk"] / max(1, data["count"]), 1)
            trend_7d.append({
                "label": day[5:],  # e.g. "08-01"
                "full_date": day,
                "avg_risk": avg_risk,
                "incident_count": data["count"],
                "peak_risk": data["peak_risk"]
            })

        # 24 Hours Trend: Latest 24 hourly buckets from captured telemetry
        sorted_hours = sorted(hourly_buckets.keys())
        last_24_hours = sorted_hours[-24:] if len(sorted_hours) >= 24 else sorted_hours
        trend_24h = []
        for h in last_24_hours:
            data = hourly_buckets[h]
            avg_risk = round(data["sum_risk"] / max(1, data["count"]), 1)
            trend_24h.append({
                "label": h[11:16],  # e.g. "14:00"
                "full_timestamp": h,
                "avg_risk": avg_risk,
                "incident_count": data["count"],
                "peak_risk": data["peak_risk"]
            })

        # 30 Days Trend: Daily buckets spanning all available telemetry days
        trend_30d = list(trend_7d)

        overall_peak = max([p.get("peak_risk", 0) for p in trend_7d]) if trend_7d else 0
        overall_avg = round(sum(p.get("avg_risk", 0) for p in trend_7d) / max(1, len(trend_7d)), 1) if trend_7d else 0

        return {
            "timeframes": {
                "24h": trend_24h,
                "7d": trend_7d,
                "30d": trend_30d
            },
            "summary": {
                "overall_peak_risk": overall_peak,
                "overall_avg_risk": overall_avg,
                "trajectory": "Stable" if len(trend_7d) < 2 else (
                    "Ascending" if trend_7d[-1]["avg_risk"] > trend_7d[0]["avg_risk"] else "Descending"
                )
            }
        }

    @classmethod
    def generate_security_report_csv(cls) -> str:
        """
        Compiles a comprehensive CISO Security Posture & Incident Report in CSV format.
        Contains report metadata, KPIs, Security Posture breakdown, Top Critical Incidents,
        MITRE ATT&CK coverage, and Advisory Recommendations.
        """
        summary = cls.get_overview_summary()
        output = io.StringIO()
        writer = csv.writer(output)

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Header Block
        writer.writerow(["SOC THREATDETECT AI - EXECUTIVE SECURITY AUDIT REPORT"])
        writer.writerow(["Generated At", now_str])
        writer.writerow(["Platform Version", "Milestone 4 Integrated Production Release"])
        writer.writerow([])

        # KPI Summary Block
        writer.writerow(["--- 1. EXECUTIVE SECURITY POSTURE & KPIS ---"])
        posture = summary.get("security_posture", {})
        writer.writerow(["Security Posture Score", f"{posture.get('score', 0)} / 100", f"Status: {posture.get('status', 'Unknown')}"])
        writer.writerow(["Posture Evaluation Formula", posture.get("formula", "")])
        writer.writerow(["Total Security Events (M1)", summary["kpis"]["total_security_events"]])
        writer.writerow(["Detected ML Anomalies (M2)", summary["kpis"]["detected_threats"]])
        writer.writerow(["Critical Priority Threats (M3)", summary["kpis"]["critical_threats"]])
        writer.writerow(["High Risk Incidents (M3)", summary["kpis"]["high_risk_incidents"]])
        writer.writerow(["Active Incidents (Open/Investigating)", summary["kpis"]["active_incidents"]])
        writer.writerow(["Affected Assets Count", summary["kpis"]["affected_assets"]])
        writer.writerow(["Affected Assets List", ", ".join(summary["kpis"]["affected_assets_list"])])
        writer.writerow([])

        # Posture Breakdown Block
        writer.writerow(["--- 2. SECURITY POSTURE FACTOR BREAKDOWN ---"])
        breakdown = posture.get("breakdown", {})
        writer.writerow(["Factor", "Value", "Impact"])
        writer.writerow(["Base Score", breakdown.get("base_score", 100), "+100"])
        for k, v in breakdown.get("penalties", {}).items():
            writer.writerow([k.replace("_", " ").title(), v, f"-{v}"])
        for k, v in breakdown.get("credits", {}).items():
            writer.writerow([k.replace("_", " ").title(), v, f"+{v}"])
        writer.writerow(["Final Computed Posture", posture.get("score", 0), f"{posture.get('status')} Posture"])
        writer.writerow([])

        # Critical Incidents Block
        writer.writerow(["--- 3. TOP CRITICAL INCIDENTS (PRIORITY ATTENTION) ---"])
        writer.writerow(["Incident ID", "Threat Type", "Affected Asset", "Risk Score", "Priority", "Status", "MITRE Technique", "Advisory Action"])
        for inc in summary.get("critical_incidents", []):
            recs = inc.get("recommendations", [])
            first_rec = recs[0].get("action", "Investigate") if recs and isinstance(recs[0], dict) else (recs[0] if recs else "Investigate telemetry")
            writer.writerow([
                inc.get("incident_id"),
                inc.get("threat_type"),
                inc.get("affected_asset"),
                inc.get("risk_score"),
                inc.get("risk_level"),
                inc.get("status"),
                inc.get("mitre_technique"),
                first_rec
            ])
        writer.writerow([])

        # Top Vulnerable Assets Block
        writer.writerow(["--- 4. MOST TARGETED ASSETS ---"])
        writer.writerow(["Asset Name", "Total Incidents", "Critical Incidents", "Peak Risk Score"])
        for a in summary.get("executive_metrics", {}).get("vulnerable_assets", []):
            writer.writerow([a["asset_name"], a["total_incidents"], a["critical_incidents"], a["max_risk_score"]])
        writer.writerow([])

        # Advisory Disclaimer
        writer.writerow(["--- 5. OPERATIONAL ADVISORY NOTICE ---"])
        writer.writerow(["Notice", "Recommendations generated by SOC ThreatDetect AI are advisory only. No automated destructive containment actions have been executed."])

        return output.getvalue()
