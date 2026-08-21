import os
import json
import pandas as pd
import numpy as np

def run_pipeline(data_dir="backend/data", output_dir="output"):
    """
    Executes complete data aggregation, cleaning, normalization, enrichment,
    MITRE ATT&CK mapping, and feature engineering pipeline.
    """
    os.makedirs(output_dir, exist_ok=True)
    summary_stats = {}

    #DATA COLLECTION
    security_path = os.path.join(data_dir, "security_events.csv")
    assets_path = os.path.join(data_dir, "assets.csv")
    threat_path = os.path.join(data_dir, "threat_intelligence.csv")
    vuln_path = os.path.join(data_dir, "vulnerabilities.csv")
    mitre_path = os.path.join(data_dir, "mitre_attack_mapping.csv")
    incident_path = os.path.join(data_dir, "incident_history.csv")

    security = pd.read_csv(security_path)
    assets = pd.read_csv(assets_path)
    threat = pd.read_csv(threat_path)
    vulnerabilities = pd.read_csv(vuln_path)
    mitre = pd.read_csv(mitre_path)
    incidents = pd.read_csv(incident_path)

    rows_before = len(security)
    summary_stats["rows_before_cleaning"] = rows_before

    #DATA CLEANING & TIMESTAMPS
    # Track duplicates
    duplicates_count = int(security.duplicated().sum())
    security.drop_duplicates(inplace=True)
    summary_stats["duplicates_removed"] = duplicates_count

    # Handle missing values in security events
    missing_before = int(security.isnull().sum().sum())
    security["vulnerability_id"] = security["vulnerability_id"].fillna("No Vulnerability")
    security["cvss_score"] = security["cvss_score"].fillna(0.0)
    security["username"] = security["username"].fillna("unknown_user")
    security["asset_name"] = security["asset_name"].fillna("Unknown Asset")
    security["department"] = security["department"].fillna("General")
    security["failed_login_attempts"] = security["failed_login_attempts"].fillna(0).astype(int)
    security["malware_detected"] = security["malware_detected"].fillna("No")
    
    missing_handled = missing_before - int(security.isnull().sum().sum())
    summary_stats["missing_values_handled"] = max(0, missing_handled)

    # Clean & validate timestamps
    invalid_timestamps = 0
    security["timestamp"] = pd.to_datetime(security["timestamp"], errors="coerce")
    null_timestamps = security["timestamp"].isnull().sum()
    if null_timestamps > 0:
        invalid_timestamps += int(null_timestamps)
        # fill invalid timestamps with mean/now
        security["timestamp"] = security["timestamp"].fillna(pd.Timestamp.now())
    
    # Sort by timestamp
    security.sort_values(by="timestamp", ascending=True, inplace=True)
    summary_stats["invalid_timestamps_handled"] = invalid_timestamps
    summary_stats["rows_after_cleaning"] = len(security)

    # Save cleaned security events
    cleaned_df = security.copy()
    cleaned_df["timestamp"] = cleaned_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    cleaned_df.to_csv(os.path.join(output_dir, "cleaned_security_events.csv"), index=False)

    #SEVERITY STANDARDIZATION & EVENT SCHEMA NORMALIZATION
    # String cleanup
    string_cols = ["event_type", "protocol", "severity", "event_status", "department", "malware_detected", "username"]
    for col in string_cols:
        if col in security.columns:
            security[col] = security[col].astype(str).str.strip()

    security["event_type"] = security["event_type"].str.title()
    security["protocol"] = security["protocol"].str.upper()
    security["event_status"] = security["event_status"].str.capitalize()
    security["username"] = security["username"].str.lower()
    security["department"] = security["department"].str.upper()

    # Normalize severity levels into: Critical, High, Medium, Low
    def normalize_severity(val):
        if not isinstance(val, str):
            return "Low"
        val_clean = val.strip().capitalize()
        if val_clean in ["Critical", "High", "Medium", "Low"]:
            return val_clean
        elif val_clean.upper() == "CRITICAL":
            return "Critical"
        elif val_clean.upper() == "HIGH":
            return "High"
        elif val_clean.upper() == "MEDIUM":
            return "Medium"
        elif val_clean.upper() == "LOW":
            return "Low"
        else:
            return "Low"

    security["severity"] = security["severity"].apply(normalize_severity)
    
    # Derive risk label based on standardized severity level
    risk_label_map = {
        "Critical": "Critical Risk",
        "High": "High Risk",
        "Medium": "Medium Risk",
        "Low": "Low Risk"
    }
    security["risk_label"] = security["severity"].map(risk_label_map).fillna("Low Risk")
    
    # Mapping event_status to standard schema field 'status'
    security["status"] = security["event_status"]

    # Save normalized dataset
    normalized_df = security.copy()
    normalized_df["timestamp"] = normalized_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    normalized_df.to_csv(os.path.join(output_dir, "normalized_security_events.csv"), index=False)

    #THREAT INTELLIGENCE ENRICHMENT
    # Join with threat_intelligence on source_ip == indicator_value
    threat_clean = threat.copy()
    threat_clean["indicator_value"] = threat_clean["indicator_value"].astype(str).str.strip()
    
    # Merge threat intel
    security = security.merge(
        threat_clean,
        how="left",
        left_on="source_ip",
        right_on="indicator_value",
        suffixes=("", "_threat_feed")
    )

    security["threat_match"] = security["indicator_id"].notna()
    security["malicious_ip_flag"] = np.where(security["threat_match"], 1, 0)
    security["threat_feed_match"] = np.where(security["threat_match"], 1, 0)

    # Threat indicator logic (matching threat intel OR rule-based high failed logins / malware)
    rule_brute_force = (security["failed_login_attempts"] >= 5) | (security["event_type"] == "Brute Force")
    rule_malware = (security["malware_detected"].str.lower() == "yes") | (security["event_type"] == "Malware Detection")

    security["threat_indicator"] = security["threat_match"] | rule_brute_force | rule_malware

    # Populate threat metadata
    security["indicator_type"] = security["indicator_type"].fillna("IP Address")
    
    def fill_threat_name(row):
        if pd.notna(row["threat_name"]) and str(row["threat_name"]).strip() != "":
            return row["threat_name"]
        if row["failed_login_attempts"] >= 5 or row["event_type"] == "Brute Force":
            return "Possible Brute Force Attack"
        if str(row["malware_detected"]).lower() == "yes":
            return "Malware Infection Alert"
        return "No Match"

    security["threat_name"] = security.apply(fill_threat_name, axis=1)
    security["threat_actor"] = security["threat_actor"].fillna("Unknown")
    security["confidence"] = security["confidence"].fillna("Unknown")
    security["threat_severity"] = security["severity_threat_feed"].fillna("Low")

    threat_matches_count = int(security["threat_match"].sum())
    summary_stats["threat_matches"] = threat_matches_count

    #MITRE ATT&CK MAPPING
    mitre_clean = mitre.copy()
    mitre_clean["event_type"] = mitre_clean["event_type"].astype(str).str.strip().str.title()
    
    security = security.merge(mitre_clean, on="event_type", how="left")
    
    security["mitre_mapped"] = np.where(security["mitre_id"].notna(), 1, 0)
    security["mitre_id"] = security["mitre_id"].fillna("Unknown")
    security["technique_name"] = security["technique_name"].fillna("Unknown")
    security["tactic"] = security["tactic"].fillna("Unknown")

    total_events = len(security)
    mapped_events = int(security["mitre_mapped"].sum())
    unmapped_events = total_events - mapped_events
    mapping_percentage = round((mapped_events / total_events) * 100, 2) if total_events > 0 else 0.0

    summary_stats["total_events"] = total_events
    summary_stats["mitre_mapped_events"] = mapped_events
    summary_stats["mitre_unmapped_events"] = unmapped_events
    summary_stats["mitre_mapping_percentage"] = mapping_percentage

    # Asset & Vulnerability & Incident Lookups Enrichment
    security = security.merge(assets, how="left", on="asset_name", suffixes=("", "_asset"))
    security = security.merge(vulnerabilities, how="left", left_on="vulnerability_id", right_on="cve_id", suffixes=("", "_vuln"))
    security = security.merge(incidents, how="left", on="event_id", suffixes=("", "_incident"))

    # Clean Incident fields
    if "incident_id" in security.columns:
        security["incident_id"] = security["incident_id"].fillna("None")
        security["incident_type"] = security["incident_type"].fillna("No Incident")
        security["assigned_to"] = security["assigned_to"].fillna("Unassigned")
        security["status_incident"] = security["status_incident"].fillna("No Incident")
        security["response_time"] = security["response_time"].fillna("N/A")
        security["resolution"] = security["resolution"].fillna("N/A")

    #FEATURE ENGINEERING
    #Failed Login Count
    security["failed_login_count"] = security["failed_login_attempts"]

    #Hour Of Day &Weekend Flag
    security["hour_of_day"] = security["timestamp"].dt.hour
    security["day_of_week"] = security["timestamp"].dt.dayofweek
    security["weekend_flag"] = np.where(security["day_of_week"] >= 5, 1, 0)

    #Severity Score
    sev_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    security["severity_score"] = security["severity"].map(sev_map).fillna(1).astype(int)

    #Number Of Alerts Per User
    user_alert_counts = security["username"].value_counts().to_dict()
    security["alerts_per_user"] = security["username"].map(user_alert_counts).fillna(1).astype(int)

    #Event Frequency (total count of events for this event_type across dataset)
    event_freq_map = security["event_type"].value_counts().to_dict()
    security["event_frequency"] = security["event_type"].map(event_freq_map).fillna(1).astype(int)

    #Malicious IP Flag & Threat Feed Match (already set)
    # CVSS Score
    if "cvss_score_vuln" in security.columns:
        security["cvss_score_final"] = security["cvss_score_vuln"].fillna(security["cvss_score"]).fillna(0.0)
    else:
        security["cvss_score_final"] = security["cvss_score"].fillna(0.0)

    has_incident = (security["incident_id"].notna()) & (security["incident_id"] != "None") & (security["incident_id"] != "nan")
    total_incidents = int(has_incident.sum())
    active_incidents = int((has_incident & (~security["status_incident"].astype(str).str.lower().isin(["closed", "resolved"]))).sum())
    closed_incidents = int((has_incident & (security["status_incident"].astype(str).str.lower().isin(["closed", "resolved"]))).sum())

    summary_stats["vulnerabilities_count"] = int(vulnerabilities["vulnerability_id"].nunique()) if "vulnerability_id" in vulnerabilities.columns else 0
    summary_stats["total_incidents_count"] = total_incidents
    summary_stats["active_incidents_count"] = active_incidents
    summary_stats["closed_incidents_count"] = closed_incidents
    summary_stats["malware_events_count"] = int((security["malware_detected"].str.lower() == "yes").sum())
    summary_stats["engineered_features"] = [
        "failed_login_count",
        "hour_of_day",
        "weekend_flag",
        "severity_score",
        "event_frequency",
        "malicious_ip_flag",
        "threat_feed_match",
        "cvss_score_final",
        "alerts_per_user"
    ]

    # Save Enriched Dataset
    enriched_df = security.copy()
    enriched_df["timestamp"] = enriched_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    enriched_df.to_csv(os.path.join(output_dir, "enriched_security_events.csv"), index=False)

    # Save Processing Summary JSON
    with open(os.path.join(output_dir, "processing_summary.json"), "w") as f:
        json.dump(summary_stats, f, indent=4)

    print(f"[Pipeline] Processed {len(security)} events successfully. Outputs saved in '{output_dir}'.")
    return summary_stats, security

if __name__ == "__main__":
    run_pipeline()
