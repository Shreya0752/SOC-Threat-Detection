"""
Verification Test Script for Milestone 2 - Step 3 (Threat Classification & Persistence).
Validates 1,800 prediction records, database persistence, idempotency, confidence scoring,
explainable reasons, and M1 API regression safety.
"""
import os
import sys
import numpy as np
import pandas as pd

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database.db import SessionLocal, init_db
from backend.models.database_models import SecurityEvent, ThreatPrediction
from backend.ml.threat_classification import process_and_persist_predictions
from backend.app import app

def run_step_3_verification():
    print("=" * 70)
    print("MILESTONE 2 - STEP 3 THREAT CLASSIFICATION & PERSISTENCE VERIFICATION")
    print("=" * 70)

    # Ensure DB tables exist
    init_db(force_reseed=False)

    # 1. Run Classification & Persistence
    print("\n[Step 3.1] Generating and persisting predictions...")
    results_df = process_and_persist_predictions()

    # 2. Query Database Records Directly
    db = SessionLocal()
    try:
        db_preds = db.query(ThreatPrediction).all()
        db_events_count = db.query(SecurityEvent).count()
        
        pred_dicts = [p.to_dict() for p in db_preds]
        df_db = pd.DataFrame(pred_dicts)
        
        total_preds = len(df_db)
        print(f"\n[DB Check] Total prediction records in SQLite: {total_preds}")
        assert total_preds == 1800, f"Expected 1800 predictions, found {total_preds}"
        assert total_preds == db_events_count, "Prediction count != SecurityEvent count!"

        # 3. Duplicate & Orphan Checks
        unique_event_ids = df_db["event_id"].nunique()
        assert unique_event_ids == 1800, f"Duplicate predictions found! Unique event_ids: {unique_event_ids}"
        
        event_ids_in_sec = set(r[0] for r in db.query(SecurityEvent.event_id).all())
        event_ids_in_pred = set(df_db["event_id"].values)
        
        orphans = event_ids_in_pred - event_ids_in_sec
        assert len(orphans) == 0, f"Orphan prediction records found: {orphans}"
        print("[DB Check] Zero duplicate event predictions and zero orphan records confirmed.")

        # 4. Value Validations
        null_conf = int(df_db["confidence_score"].isnull().sum())
        null_anom = int(df_db["anomaly_score"].isnull().sum())
        inf_anom = int(np.isinf(df_db["anomaly_score"]).sum())

        assert null_conf == 0, "NaN confidence scores found!"
        assert null_anom == 0, "NaN anomaly scores found!"
        assert inf_anom == 0, "Inf anomaly scores found!"

        min_conf = float(df_db["confidence_score"].min())
        max_conf = float(df_db["confidence_score"].max())
        mean_conf = float(df_db["confidence_score"].mean())
        median_conf = float(df_db["confidence_score"].median())

        assert 0.0 <= min_conf <= 100.0, f"Confidence score out of range: {min_conf}"
        assert 0.0 <= max_conf <= 100.0, f"Confidence score out of range: {max_conf}"

        valid_preds = set(df_db["prediction"].unique())
        assert valid_preds.issubset({"Normal", "Anomalous"}), f"Invalid prediction labels: {valid_preds}"

        valid_severities = set(df_db["severity"].unique())
        assert valid_severities.issubset({"Low", "Medium", "High", "Critical"}), f"Invalid severities: {valid_severities}"

        # Explanation check
        has_reasons = df_db["explanation"].apply(lambda x: isinstance(x, list) and len(x) > 0).all()
        assert has_reasons, "Found prediction records missing explainable reasons!"
        print(f"[Validation Check] All 1800 records contain valid explainable reasons.")

        # 5. Idempotency Check (Run a second time, verify row count stays 1800)
        print("\n[Step 3.2] Testing Idempotency (Re-running persistence)...")
        process_and_persist_predictions()
        total_preds_after = db.query(ThreatPrediction).count()
        assert total_preds_after == 1800, f"Idempotency failed! Total predictions grew to {total_preds_after}"
        print("[Idempotency Check] Idempotency confirmed: row count remains exactly 1800.")

        # 6. Statistical Summary
        normal_cnt = int((df_db["prediction"] == "Normal").sum())
        anom_cnt = int((df_db["prediction"] == "Anomalous").sum())
        anom_pct = round((anom_cnt / total_preds) * 100, 2)

        print("\n" + "=" * 70)
        print("MILESTONE 2 - STEP 3 STATISTICAL SUMMARY")
        print("=" * 70)
        print(f"Total Predictions:    {total_preds}")
        print(f"Normal Events:        {normal_cnt}")
        print(f"Anomalous Events:     {anom_cnt} ({anom_pct}%)")

        print("\nThreat Type Distribution:")
        threat_type_counts = df_db["threat_type"].value_counts()
        for tt, cnt in threat_type_counts.items():
            print(f"  - {tt:<22}: {cnt}")

        print("\nThreat Level Distribution:")
        severity_counts = df_db["severity"].value_counts()
        for sev in ["Low", "Medium", "High", "Critical"]:
            cnt = severity_counts.get(sev, 0)
            print(f"  - {sev:<10}: {cnt}")

        print("\nConfidence Score Statistics:")
        print(f"  - Minimum: {min_conf:.1f}%")
        print(f"  - Maximum: {max_conf:.1f}%")
        print(f"  - Mean:    {mean_conf:.1f}%")
        print(f"  - Median:  {median_conf:.1f}%")

    finally:
        db.close()

    # 7. M1 API Regression Check
    print("\n" + "-" * 70)
    print("M1 API REGRESSION CHECK")
    print("-" * 70)
    client = app.test_client()

    login_res = client.post('/login', json={'username': 'analyst_admin', 'password': 'soc12345'})
    print(f"POST /login:  HTTP {login_res.status_code}")
    assert login_res.status_code == 200, "Login failed!"

    events_res = client.get('/events')
    print(f"GET /events:  HTTP {events_res.status_code} (Returned {events_res.get_json().get('total')} events)")
    assert events_res.status_code == 200, "GET /events failed!"

    stats_res = client.get('/stats')
    print(f"GET /stats:   HTTP {stats_res.status_code}")
    assert stats_res.status_code == 200, "GET /stats failed!"

    threats_res = client.get('/threats')
    print(f"GET /threats: HTTP {threats_res.status_code}")
    assert threats_res.status_code == 200, "GET /threats failed!"

    print("\n" + "=" * 70)
    print("VERIFICATION SUCCESSFUL: ALL STEP 3 CHECKS PASSED")
    print("=" * 70)

if __name__ == "__main__":
    run_step_3_verification()
