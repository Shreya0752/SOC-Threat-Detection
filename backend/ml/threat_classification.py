"""
Threat Classification, Confidence Scoring, and Persistence Engine for Milestone 2.
Combines Isolation Forest anomaly predictions with rule-based security indicators to output:
- threat_type
- threat_level (severity)
- calibrated confidence_score (0-100)
- explainable reason codes
And persists results idempotently into the SQLite database.
"""
import os
import sys
import json
from datetime import datetime, timezone
import pandas as pd
import numpy as np

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database.db import SessionLocal, init_db
from backend.models.database_models import SecurityEvent, ThreatPrediction
from backend.ml.feature_selection import load_m1_events_from_db, extract_features
from backend.ml.model_loader import load_model, load_preprocessor, save_model, save_preprocessor
from backend.ml.anomaly_detection import AnomalyDetector, train_isolation_forest_pipeline

MODEL_VERSION = "isolation_forest_v1"

def classify_event(event_row, prediction_label, anomaly_score):
    """
    Classifies a single security event using Isolation Forest prediction and M1 security indicators.
    
    Returns:
        dict containing:
            - prediction: 'Normal' or 'Anomalous'
            - threat_type: Categorized threat name
            - severity: Threat level ('Low', 'Medium', 'High', 'Critical')
            - confidence_score: Calibrated float 0.0 - 100.0
            - reasons: list of explainable string reason codes
    """
    # Extract feature attributes with fallbacks
    failed_logins = int(event_row.get("failed_login_count", event_row.get("failed_login_attempts", 0)))
    severity_m1 = str(event_row.get("severity", "Low")).capitalize()
    sev_score = int(event_row.get("severity_score", 1))
    
    malware_str = str(event_row.get("malware_detected", "No")).lower().strip()
    malware_detected = (malware_str == "yes")
    
    cvss = float(event_row.get("cvss_score_final", event_row.get("cvss_score", 0.0)))
    evt_type = str(event_row.get("event_type", "")).strip()
    
    malicious_ip = bool(event_row.get("malicious_ip_flag", 0) or event_row.get("threat_match", False))
    after_hours = int(event_row.get("after_hours_flag", 0))
    impossible_travel = int(event_row.get("impossible_travel_flag", 0))

    is_anomalous = (prediction_label == "Anomalous")
    
    # ----------------------------------------------------
    # 1. THREAT TYPE ASSIGNMENT (Deterministic Rules)
    # ----------------------------------------------------
    evt_type_lower = evt_type.lower()
    
    if "brute force" in evt_type_lower or (failed_logins >= 5 and is_anomalous):
        threat_type = "Brute Force"
    elif malware_detected or "malware" in evt_type_lower:
        threat_type = "Malware"
    elif "sql injection" in evt_type_lower:
        threat_type = "SQL Injection"
    elif "phishing" in evt_type_lower:
        threat_type = "Phishing"
    elif "privilege escalation" in evt_type_lower:
        threat_type = "Privilege Escalation"
    elif malicious_ip:
        threat_type = "Malicious IP Activity"
    elif is_anomalous:
        threat_type = "Anomalous Activity"
    else:
        threat_type = "Normal Activity"

    # ----------------------------------------------------
    # 2. THREAT LEVEL / SEVERITY CLASSIFICATION
    # ----------------------------------------------------
    if is_anomalous:
        if severity_m1 == "Critical" or cvss >= 9.0 or (malware_detected and failed_logins >= 5):
            threat_severity = "Critical"
        elif severity_m1 == "High" or failed_logins >= 10 or malware_detected or cvss >= 7.0:
            threat_severity = "High"
        elif severity_m1 == "Medium" or after_hours == 1 or failed_logins >= 5:
            threat_severity = "Medium"
        else:
            threat_severity = "Low"
    else:
        # For Normal predictions, retain M1 baseline severity
        threat_severity = severity_m1 if severity_m1 in ["Low", "Medium", "High", "Critical"] else "Low"

    # ----------------------------------------------------
    # 3. CONFIDENCE SCORE (0.0 – 100.0)
    # ----------------------------------------------------
    # Base score
    score = 50.0 if is_anomalous else 10.0
    
    # Failed logins contribution
    if failed_logins >= 15:
        score += 25.0
    elif failed_logins >= 5:
        score += 15.0
    elif failed_logins > 0:
        score += 5.0
        
    # Malware contribution
    if malware_detected:
        score += 20.0
        
    # CVSS contribution
    if cvss > 0:
        score += min(20.0, cvss * 2.0)
        
    # Severity score contribution
    score += (sev_score * 4.0)
    
    # Off-hours contribution
    if after_hours == 1:
        score += 5.0
        
    # Malicious IP contribution
    if malicious_ip:
        score += 15.0

    # Impossible travel contribution
    if impossible_travel == 1:
        score += 20.0

    confidence_score = round(float(np.clip(score, 0.0, 100.0)), 1)

    # ----------------------------------------------------
    # 4. EXPLAINABLE REASONS
    # ----------------------------------------------------
    reasons = []
    if is_anomalous:
        reasons.append(f"Isolation Forest model flagged anomalous behavior (score: {anomaly_score:.4f})")
    else:
        reasons.append("Baseline behavioral activity within normal parameters")
        
    if failed_logins >= 5:
        reasons.append(f"Multiple failed authentication attempts ({failed_logins} failed logins)")
    elif failed_logins > 0:
        reasons.append(f"Recorded failed login attempts ({failed_logins})")
        
    if malware_detected:
        reasons.append("Malware infection indicator detected on host")
        
    if cvss >= 7.0:
        reasons.append(f"High-risk CVE vulnerability associated (CVSS: {cvss:.1f})")
    elif cvss > 0:
        reasons.append(f"Known CVE vulnerability associated (CVSS: {cvss:.1f})")
        
    if severity_m1 in ["High", "Critical"]:
        reasons.append(f"Elevated event severity rating ({severity_m1})")
        
    if after_hours == 1:
        reasons.append("Off-hours or weekend activity indicator")
        
    if malicious_ip:
        reasons.append("Source IP matched threat intelligence feed")
        
    if impossible_travel == 1:
        reasons.append("Impossible travel anomaly detected across geographic regions")

    return {
        "prediction": prediction_label,
        "threat_type": threat_type,
        "severity": threat_severity,
        "confidence_score": confidence_score,
        "anomaly_score": float(round(anomaly_score, 4)),
        "reasons": reasons
    }

def process_and_persist_predictions(db_session=None):
    """
    Runs full feature extraction, Isolation Forest inference, threat classification,
    and persists prediction records into SQLite threat_predictions table idempotently.
    """
    close_session = False
    if db_session is None:
        db_session = SessionLocal()
        close_session = True

    try:
        # Load M1 events from DB
        df_events = load_m1_events_from_db(db_session)
        event_ids, X_raw = extract_features(df_events)
        
        # Load model and preprocessor artifacts (or train if missing)
        try:
            model = load_model()
            preprocessor = load_preprocessor()
        except Exception:
            print("[Classification] Saved model artifact not found. Running training pipeline...")
            detector, preprocessor, _ = train_isolation_forest_pipeline(save_artifacts=True)
            model = detector.model

        # Execute ML preprocessing & inference
        X_processed = preprocessor.transform(X_raw)
        raw_preds = model.predict(X_processed)
        labels = np.where(raw_preds == 1, "Normal", "Anomalous")
        scores = model.decision_function(X_processed)

        current_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Query existing predictions to ensure idempotency (update if present, insert if missing)
        existing_preds = {
            p.event_id: p for p in db_session.query(ThreatPrediction).all()
        }

        records_to_add = []
        classification_results = []

        for idx, row in df_events.iterrows():
            evt_id = str(row["event_id"])
            pred_label = labels[idx]
            anom_score = float(scores[idx])

            classified = classify_event(row, pred_label, anom_score)
            classified["event_id"] = evt_id
            classification_results.append(classified)

            explanation_json = json.dumps(classified["reasons"])

            if evt_id in existing_preds:
                # Update existing record
                pred_obj = existing_preds[evt_id]
                pred_obj.prediction = classified["prediction"]
                pred_obj.threat_type = classified["threat_type"]
                pred_obj.confidence_score = classified["confidence_score"]
                pred_obj.anomaly_score = classified["anomaly_score"]
                pred_obj.severity = classified["severity"]
                pred_obj.model_version = MODEL_VERSION
                pred_obj.prediction_timestamp = current_timestamp
                pred_obj.explanation = explanation_json
            else:
                # Create new record
                pred_obj = ThreatPrediction(
                    event_id=evt_id,
                    prediction=classified["prediction"],
                    threat_type=classified["threat_type"],
                    confidence_score=classified["confidence_score"],
                    anomaly_score=classified["anomaly_score"],
                    severity=classified["severity"],
                    model_version=MODEL_VERSION,
                    prediction_timestamp=current_timestamp,
                    explanation=explanation_json
                )
                records_to_add.append(pred_obj)

        if records_to_add:
            db_session.bulk_save_objects(records_to_add)

        db_session.commit()
        print(f"[Classification] Successfully persisted predictions into database. Total: {len(df_events)}")
        
        return pd.DataFrame(classification_results)

    except Exception as e:
        db_session.rollback()
        print(f"[Classification Error] Failed to persist predictions: {e}")
        raise e
    finally:
        if close_session:
            db_session.close()

if __name__ == "__main__":
    init_db(force_reseed=False)
    results_df = process_and_persist_predictions()
    print("[Classification] First 5 predictions:")
    print(results_df.head())
