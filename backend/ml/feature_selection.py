import os
import sys
import pandas as pd
import numpy as np
from datetime import datetime, timezone

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database.db import SessionLocal
from backend.models.database_models import SecurityEvent

def load_m1_events_from_db(db_session=None):
    """
    Loads all processed security event records directly from the M1 SQLite database.
    Does NOT read raw CSV as primary source; uses database records.
    """
    close_session = False
    if db_session is None:
        db_session = SessionLocal()
        close_session = True

    try:
        events = db_session.query(SecurityEvent).all()
        event_dicts = [evt.to_dict() for evt in events]
        df = pd.DataFrame(event_dicts)
        
        # Pull engineered features if nested inside dict
        if "engineered_features" in df.columns:
            eng_df = pd.json_normalize(df["engineered_features"])
            for col in eng_df.columns:
                if col not in df.columns or df[col].isnull().all():
                    df[col] = eng_df[col]
        return df
    finally:
        if close_session:
            db_session.close()

def extract_features(df):
    """
    Extracts and derives M2 machine learning features from M1 security events DataFrame.
    
    Returns:
        event_ids (pd.Series): Event identifiers (preserved separately, not included in ML matrix).
        X_features (pd.DataFrame): Raw feature matrix containing numerical and categorical ML features.
    """
    df = df.copy()

    # Ensure fallback defaults for optional raw dictionary keys
    for col, default_val in [
        ("event_id", f"EVT_LIVE_{int(datetime.now().timestamp())}"),
        ("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
        ("source_ip", "127.0.0.1"),
        ("destination_ip", "10.0.0.1"),
        ("username", "analyst_admin"),
        ("event_type", "Unknown"),
        ("severity", "Medium"),
        ("malware_detected", "No"),
        ("cvss_score", 0.0),
        ("protocol", "TCP")
    ]:
        if col not in df.columns:
            df[col] = default_val
    
    # 1. Event IDs (Preserved separately for linkage)
    event_ids = df["event_id"]
    
    # 2. Extract / Compute Required M2 Features:
    
    # Feature 1: failed_login_count
    if "failed_login_count" in df.columns and not df["failed_login_count"].isnull().all():
        failed_login_count = df["failed_login_count"].fillna(0).astype(int)
    else:
        failed_login_count = df["failed_login_attempts"].fillna(0).astype(int)

    # Feature 2: hour_of_day
    if "hour_of_day" in df.columns and not df["hour_of_day"].isnull().all():
        hour_of_day = df["hour_of_day"].fillna(0).astype(int)
    else:
        timestamps = pd.to_datetime(df["timestamp"], errors="coerce")
        hour_of_day = timestamps.dt.hour.fillna(0).astype(int)

    # Weekend flag for after_hours derivation
    if "weekend_flag" in df.columns and not df["weekend_flag"].isnull().all():
        weekend_flag = df["weekend_flag"].fillna(0).astype(int)
    else:
        timestamps = pd.to_datetime(df["timestamp"], errors="coerce")
        dayofweek = timestamps.dt.dayofweek.fillna(0)
        weekend_flag = np.where(dayofweek >= 5, 1, 0)

    # Feature 3: after_hours_flag
    # Definition: 1 if hour_of_day < 8 OR hour_of_day > 18 OR weekend_flag == 1 else 0
    after_hours_flag = np.where(
        (hour_of_day < 8) | (hour_of_day > 18) | (weekend_flag == 1), 1, 0
    )

    # Feature 4: severity_score (Low=1, Medium=2, High=3, Critical=4)
    if "severity_score" in df.columns and not df["severity_score"].isnull().all():
        severity_score = df["severity_score"].fillna(1).astype(int)
    else:
        sev_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        severity_score = df["severity"].map(sev_map).fillna(1).astype(int)

    # Feature 5: event_frequency
    if "event_frequency" in df.columns and not df["event_frequency"].isnull().all():
        event_frequency = df["event_frequency"].fillna(1).astype(int)
    else:
        freq_map = df["event_type"].value_counts().to_dict()
        event_frequency = df["event_type"].map(freq_map).fillna(1).astype(int)

    # Feature 6: alerts_per_user
    if "alerts_per_user" in df.columns and not df["alerts_per_user"].isnull().all():
        alerts_per_user = df["alerts_per_user"].fillna(1).astype(int)
    else:
        user_counts = df["username"].value_counts().to_dict()
        alerts_per_user = df["username"].map(user_counts).fillna(1).astype(int)

    # Feature 7: malicious_ip_flag
    if "malicious_ip_flag" in df.columns and not df["malicious_ip_flag"].isnull().all():
        malicious_ip_flag = df["malicious_ip_flag"].fillna(0).astype(int)
    else:
        malicious_ip_flag = np.where(df.get("threat_match", False), 1, 0)

    # Feature 8: malware_detected_encoded (Yes -> 1, No -> 0)
    malware_str = df["malware_detected"].astype(str).str.lower().str.strip()
    malware_detected_encoded = np.where(malware_str == "yes", 1, 0)

    # Feature 9: cvss_score_final
    if "cvss_score_final" in df.columns and not df["cvss_score_final"].isnull().all():
        cvss_score_final = df["cvss_score_final"].fillna(0.0).astype(float)
    else:
        cvss_score_final = df["cvss_score"].fillna(0.0).astype(float)

    # Feature 10: impossible_travel_flag
    # Rule-based evaluation checking consecutive country changes per user within short time windows (< 2 hours).
    # Since all records in current dataset originate from 'India', this cleanly evaluates to 0 without inventing fake coordinates.
    impossible_travel_flag = calculate_impossible_travel(df)

    # Feature 11: protocol (categorical)
    protocol = df["protocol"].fillna("TCP").astype(str).str.upper().str.strip()

    # Construct Raw Feature DataFrame
    X_features = pd.DataFrame({
        "failed_login_count": failed_login_count,
        "hour_of_day": hour_of_day,
        "after_hours_flag": after_hours_flag,
        "severity_score": severity_score,
        "event_frequency": event_frequency,
        "alerts_per_user": alerts_per_user,
        "malicious_ip_flag": malicious_ip_flag,
        "malware_detected_encoded": malware_detected_encoded,
        "cvss_score_final": cvss_score_final,
        "impossible_travel_flag": impossible_travel_flag,
        "protocol": protocol
    })

    return event_ids, X_features

def calculate_impossible_travel(df, time_threshold_minutes=120):
    """
    Derives impossible_travel_flag by sorting events per username and identifying
    rapid source_country changes within time_threshold_minutes.
    Returns array of 0 or 1 per event index.
    """
    if "source_country" not in df.columns or "username" not in df.columns or "timestamp" not in df.columns:
        return np.zeros(len(df), dtype=int)
    
    temp_df = df[["username", "timestamp", "source_country"]].copy()
    temp_df["orig_idx"] = temp_df.index
    temp_df["timestamp"] = pd.to_datetime(temp_df["timestamp"], errors="coerce")
    temp_df = temp_df.sort_values(by=["username", "timestamp"])

    temp_df["prev_user"] = temp_df["username"].shift(1)
    temp_df["prev_country"] = temp_df["source_country"].shift(1)
    temp_df["prev_time"] = temp_df["timestamp"].shift(1)

    same_user = (temp_df["username"] == temp_df["prev_user"])
    country_change = (temp_df["source_country"].notna()) & (temp_df["prev_country"].notna()) & (temp_df["source_country"] != temp_df["prev_country"])
    time_diff_min = (temp_df["timestamp"] - temp_df["prev_time"]).dt.total_seconds() / 60.0

    flagged = same_user & country_change & (time_diff_min < time_threshold_minutes)
    temp_df["impossible_travel_flag"] = np.where(flagged, 1, 0)
    
    # Restore original dataset row order
    temp_df = temp_df.sort_values(by="orig_idx")
    return temp_df["impossible_travel_flag"].values

if __name__ == "__main__":
    print("[Feature Selection] Loading M1 data from database...")
    df_events = load_m1_events_from_db()
    event_ids, X_raw = extract_features(df_events)
    print(f"[Feature Selection] Loaded {len(df_events)} events.")
    print("[Feature Selection] Raw Feature Matrix Head:")
    print(X_raw.head())
