"""
Verification Test Script for Milestone 2 - Step 2 (Isolation Forest Anomaly Detection).
Validates model training, artifact persistence, reproducibility, prediction outputs,
unsupervised summary statistics, and M1 API regression safety.
"""
import os
import sys
import numpy as np
import pandas as pd

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database.db import SessionLocal
from backend.models.database_models import SecurityEvent, ThreatPrediction
from backend.ml.feature_selection import load_m1_events_from_db, extract_features
from backend.ml.preprocessing import ThreatDataPreprocessor
from backend.ml.anomaly_detection import AnomalyDetector, train_isolation_forest_pipeline
from backend.ml.model_loader import load_model, load_preprocessor
from backend.app import app

def run_step_2_verification():
    print("=" * 70)
    print("MILESTONE 2 - STEP 2 ISOLATION FOREST VERIFICATION")
    print("=" * 70)

    # 1. Load M1 events from SQLite
    df_events = load_m1_events_from_db()
    event_ids, X_raw = extract_features(df_events)
    total_events = len(df_events)

    print(f"\n[Step 2.1 - Data Input] M1 Security Events loaded: {total_events}")
    print(f"Raw feature matrix shape: {X_raw.shape}")

    # 2. Train Isolation Forest and Save Artifacts
    detector, preprocessor, results_df = train_isolation_forest_pipeline(save_artifacts=True)
    X_processed = preprocessor.transform(X_raw)

    print(f"Processed feature matrix shape: {X_processed.shape}")
    print(f"Number of estimators: {detector.model.n_estimators}")
    print(f"Random state: {detector.model.random_state}")

    # 3. Artifact Persistence Check
    model_path = os.path.join(PROJECT_ROOT, "backend/models/ml_models/isolation_forest_v1.pkl")
    preproc_path = os.path.join(PROJECT_ROOT, "backend/models/ml_models/preprocessing_v1.pkl")
    
    assert os.path.exists(model_path), f"Model artifact missing at {model_path}"
    assert os.path.exists(preproc_path), f"Preprocessor artifact missing at {preproc_path}"
    print(f"[Artifact Check] Model artifact confirmed: {model_path}")
    print(f"[Artifact Check] Preprocessor artifact confirmed: {preproc_path}")

    # 4. Loader Verification
    loaded_model = load_model(model_path)
    loaded_preproc = load_preprocessor(preproc_path)
    X_reloaded = loaded_preproc.transform(X_raw)
    reloaded_raw_preds = loaded_model.predict(X_reloaded)
    reloaded_labels = np.where(reloaded_raw_preds == 1, "Normal", "Anomalous")
    reloaded_scores = loaded_model.decision_function(X_reloaded)

    # 5. Reproducibility Test
    # Train second model with same random_state=42
    detector2 = AnomalyDetector(n_estimators=200, contamination="auto", random_state=42)
    detector2.fit(X_processed)
    preds2 = detector2.predict(X_processed)
    scores2 = detector2.compute_anomaly_scores(X_processed)

    reproducible_labels = np.array_equal(results_df["prediction"].values, preds2)
    reproducible_scores = np.allclose(results_df["anomaly_score"].values, scores2)
    print(f"[Reproducibility] Second run labels identical: {reproducible_labels}")
    print(f"[Reproducibility] Second run scores identical: {reproducible_scores}")

    # 6. Basic Validation
    pred_count = len(results_df["prediction"])
    score_count = len(results_df["anomaly_score"])
    null_scores = int(np.isnan(results_df["anomaly_score"]).sum())
    inf_scores = int(np.isinf(results_df["anomaly_score"]).sum())
    unique_preds = set(results_df["prediction"].unique())

    assert pred_count == total_events, f"Prediction count {pred_count} != event count {total_events}"
    assert score_count == total_events, f"Score count {score_count} != event count {total_events}"
    assert null_scores == 0, "NaN scores found!"
    assert inf_scores == 0, "Inf scores found!"
    assert unique_preds.issubset({"Normal", "Anomalous"}), f"Invalid labels found: {unique_preds}"
    assert reproducible_labels, "Reproducibility check failed!"
    assert reproducible_scores, "Reproducibility score check failed!"

    # 7. Unsupervised Statistics Summary
    normal_cnt = int((results_df["prediction"] == "Normal").sum())
    anom_cnt = int((results_df["prediction"] == "Anomalous").sum())
    anom_pct = round((anom_cnt / total_events) * 100, 2)
    
    min_score = float(results_df["anomaly_score"].min())
    max_score = float(results_df["anomaly_score"].max())
    mean_score = float(results_df["anomaly_score"].mean())
    median_score = float(results_df["anomaly_score"].median())

    print("\n" + "-" * 70)
    print("ISOLATION FOREST STATISTICAL SUMMARY")
    print("-" * 70)
    print(f"Total events:          {total_events}")
    print(f"Normal events:         {normal_cnt}")
    print(f"Anomalous events:      {anom_cnt}")
    print(f"Anomaly percentage:    {anom_pct}%")
    print(f"Min anomaly score:     {min_score:.4f}")
    print(f"Max anomaly score:     {max_score:.4f}")
    print(f"Mean anomaly score:    {mean_score:.4f}")
    print(f"Median anomaly score:  {median_score:.4f}")

    # 8. Confirm DB Table NOT Populated Yet (Step 3 requirement)
    db = SessionLocal()
    try:
        table_preds = db.query(ThreatPrediction).count()
        print(f"\n[Persistence Check] threat_predictions row count in DB: {table_preds} (Should be 0 for Step 2)")
        assert table_preds == 0, "DB table was populated prematurely!"
    finally:
        db.close()

    # 9. M1 API Regression Check
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
    print("VERIFICATION SUCCESSFUL: ALL STEP 2 CHECKS PASSED")
    print("=" * 70)

if __name__ == "__main__":
    run_step_2_verification()
