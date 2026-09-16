"""
Event Correlation & Multi-Stage Attack Chain Module for Milestone 3 (`backend/risk/correlation.py`).
Correlates security events within temporal windows (5–30 mins) based on:
(username, source_ip, destination_ip, asset_name, MITRE tactics)
and maps multi-stage attack scenarios without treating alerts as isolated occurrences.
"""
from datetime import datetime
from typing import List, Dict, Any, Tuple

# MITRE Technique / Tactic Mapping for Attack Chain Detection
MITRE_TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]

EVENT_TACTIC_MAP = {
    "port scan": ("Reconnaissance", "T1046", "Network Service Scanning"),
    "phishing email": ("Initial Access", "T1566", "Phishing"),
    "sql injection attempt": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "malware detection": ("Execution", "T1204", "User Execution: Malicious File"),
    "usb device connected": ("Initial Access", "T1091", "Replication Through Removable Media"),
    "failed login": ("Credential Access", "T1110", "Brute Force: Credential Guessing"),
    "brute force": ("Credential Access", "T1110", "Brute Force: Password Spraying"),
    "login success": ("Initial Access", "T1078", "Valid Accounts"),
    "privilege escalation": ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
    "file access": ("Collection", "T1005", "Data from Local System")
}

class EventCorrelationEngine:
    """Correlates security events into cohesive multi-stage incidents."""

    @staticmethod
    def parse_timestamp(ts_val: Any) -> datetime:
        """Parses event timestamp string to datetime object."""
        if isinstance(ts_val, datetime):
            return ts_val
        ts_str = str(ts_val).strip()
        for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d"]:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        return datetime.utcnow()

    @classmethod
    def get_event_tactic_info(cls, event: Dict[str, Any]) -> Tuple[str, str, str]:
        """Resolves Tactic, MITRE ID, and Technique Name for an event."""
        # 1. Check if event has existing MITRE mappings
        mitre_id = str(event.get("mitre_id", "")).strip()
        tactic = str(event.get("tactic", "")).strip()
        tech_name = str(event.get("technique_name", "")).strip()

        if mitre_id and mitre_id not in ["Unknown", "nan", "None"]:
            return tactic, mitre_id, tech_name

        # 2. Lookup standard event type mapping
        evt_type = str(event.get("event_type", "")).strip().lower()
        if evt_type in EVENT_TACTIC_MAP:
            return EVENT_TACTIC_MAP[evt_type]

        return "Unknown Tactic", "T1000", "Generic Security Event"

    @classmethod
    def identify_attack_chain_scenario(cls, events: List[Dict[str, Any]]) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Analyzes a sequence of chronologically ordered events to identify
        multi-stage attack patterns (Brute Force, Privilege Escalation, Data Exfiltration, etc.).
        """
        sorted_evts = sorted(events, key=lambda e: cls.parse_timestamp(e.get("timestamp", "")))
        event_types = [str(e.get("event_type", "")).strip().lower() for e in sorted_evts]
        tactics = []
        chain_stages = []

        for evt in sorted_evts:
            tac, mid, mname = cls.get_event_tactic_info(evt)
            tactics.append(tac)
            chain_stages.append({
                "stage": tac,
                "event_id": evt.get("event_id"),
                "timestamp": evt.get("timestamp"),
                "event_type": evt.get("event_type"),
                "asset_name": evt.get("asset_name"),
                "mitre_id": mid,
                "technique_name": mname,
                "severity": evt.get("severity", "Low"),
                "source_ip": evt.get("source_ip", "")
            })

        # Pattern 1: Brute Force Chain
        has_failed = any(et in ["failed login", "brute force"] for et in event_types)
        has_success = "login success" in event_types
        if has_failed and has_success:
            return "Possible Brute Force Attack Chain", chain_stages
        elif sum(1 for et in event_types if et in ["failed login", "brute force"]) >= 2:
            return "Possible Brute Force Credential Spraying", chain_stages

        # Pattern 2: Privilege Escalation Chain
        has_priv_esc = "privilege escalation" in event_types
        has_init_or_access = any(et in ["sql injection attempt", "phishing email", "login success", "port scan"] for et in event_types)
        if has_priv_esc and has_init_or_access:
            return "Possible Privilege Escalation Attack Chain", chain_stages
        elif has_priv_esc:
            return "Possible Privilege Escalation Activity", chain_stages

        # Pattern 3: Data Exfiltration Chain
        has_collection = "file access" in event_types
        has_lateral_or_scan = any(et in ["port scan", "privilege escalation", "login success"] for et in event_types)
        if has_collection and has_lateral_or_scan:
            return "Possible Data Exfiltration Attack Chain", chain_stages

        # Pattern 4: Malware Infection Chain
        has_malware = any("malware" in et or str(e.get("malware_detected", "")).lower() == "yes" for et, e in zip(event_types, sorted_evts))
        has_entry = any(et in ["phishing email", "usb device connected"] for et in event_types)
        if has_malware and has_entry:
            return "Possible Malware Infection & Propagation Chain", chain_stages
        elif has_malware:
            return "Possible Malware Incident", chain_stages

        # Multi-technique scenario
        unique_tactics = set(tactics) - {"Unknown Tactic"}
        if len(unique_tactics) >= 2:
            return "Possible Multi-Stage Attack Chain", chain_stages

        # Fallback to dominant threat type
        primary_threat = sorted_evts[0].get("m2_threat_type") or sorted_evts[0].get("event_type") or "Security Alert"
        return f"Correlated {primary_threat} Incident", chain_stages

    @classmethod
    def correlate_events(cls, events: List[Dict[str, Any]], window_minutes: int = 30) -> List[Dict[str, Any]]:
        """
        Groups security events within sliding temporal window (5-30 minutes)
        matching by (username, asset_name) or (source_ip, asset_name).
        """
        if not events:
            return []

        # Sort all events chronologically
        sorted_events = sorted(events, key=lambda e: cls.parse_timestamp(e.get("timestamp", "")))

        # Group by entity keys: (username, asset_name)
        entity_groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        for evt in sorted_events:
            user = str(evt.get("username", "unknown")).strip().lower()
            asset = str(evt.get("asset_name", "unknown")).strip()
            key = (user, asset)
            if key not in entity_groups:
                entity_groups[key] = []
            entity_groups[key].append(evt)

        correlated_clusters = []

        # Temporal sliding window within each entity group
        for (user, asset), evts in entity_groups.items():
            current_cluster = []
            for evt in evts:
                evt_time = cls.parse_timestamp(evt.get("timestamp", ""))
                if not current_cluster:
                    current_cluster.append(evt)
                else:
                    last_time = cls.parse_timestamp(current_cluster[-1].get("timestamp", ""))
                    diff_mins = (evt_time - last_time).total_seconds() / 60.0
                    if 0.0 <= diff_mins <= float(window_minutes):
                        current_cluster.append(evt)
                    else:
                        if len(current_cluster) >= 1:
                            correlated_clusters.append(current_cluster)
                        current_cluster = [evt]
            if current_cluster:
                correlated_clusters.append(current_cluster)

        return correlated_clusters
