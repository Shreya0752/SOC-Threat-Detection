"""
Comprehensive REST API Test Suite for Milestone 2 - Step 4.
Tests all 6 M2 endpoints (POST /predict, GET /predictions, GET /predictions/{event_id},
GET /anomalies, GET /model-performance, GET /threat-summary) and re-tests M1 endpoints.
"""
import os
import sys
import json
import pandas as pd

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.app import app
from backend.database.db import SessionLocal, init_db
from backend.models.database_models import SecurityEvent, ThreatPrediction

def run_api_tests():
    print("=" * 70)
    print("MILESTONE 2 - STEP 4 REST API TESTING & INTEGRITY AUDIT")
    print("=" * 70)

    # Ensure DB tables exist
    init_db(force_reseed=False)

    client = app.test_client()

    # Step 1: Login
    login_res = client.post("/login", json={"username": "analyst_admin", "password": "soc12345"})
    assert login_res.status_code == 200, "Login failed!"

    api_results = []

    # Helper function to audit API calls
    def test_endpoint(name, method, url, body=None):
        if method == "POST":
            res = client.post(url, json=body)
        else:
            res = client.get(url)

        status = res.status_code
        try:
            data = res.get_json()
            is_json = True
        except Exception:
            data = None
            is_json = False

        db_backed = True if status == 200 and data is not None else False
        result = "PASS" if status in [200, 404] and is_json else "FAIL"

        api_results.append({
            "Endpoint": name,
            "HTTP": status,
            "JSON": "YES" if is_json else "NO",
            "DB-backed": "YES" if db_backed else "NO",
            "Result": result
        })
        return res, data

    # 1. POST /predict
    print("\n[Testing 1/6] POST /predict")
    p_res, p_data = test_endpoint("POST /predict", "POST", "/predict", {"event_id": "EVT00001"})
    assert p_res.status_code == 200, f"POST /predict failed with status {p_res.status_code}"
    assert p_data.get("event_id") == "EVT00001", "Returned wrong event_id!"
    assert "prediction" in p_data and "confidence_score" in p_data, "Missing prediction keys!"

    # 2. GET /predictions
    print("[Testing 2/6] GET /predictions")
    preds_res, preds_data = test_endpoint("GET /predictions", "GET", "/predictions?page=1&limit=10")
    assert preds_res.status_code == 200, f"GET /predictions failed: {preds_res.status_code}"
    assert preds_data.get("total") == 1800, f"Total predictions mismatch: {preds_data.get('total')}"
    assert len(preds_data.get("predictions", [])) == 10, "Limit pagination mismatch!"

    # 3. GET /predictions/{event_id}
    print("[Testing 3/6] GET /predictions/{event_id}")
    pred1_res, pred1_data = test_endpoint("GET /predictions/{event_id}", "GET", "/predictions/EVT00001")
    assert pred1_res.status_code == 200, "GET /predictions/EVT00001 failed!"
    assert pred1_data.get("event_id") == "EVT00001", "Wrong event ID returned!"

    # Test 404 for invalid event
    invalid_res = client.get("/predictions/EVT99999")
    assert invalid_res.status_code == 404, "Invalid event_id should return 404!"
    assert "error" in invalid_res.get_json(), "Missing error key in 404 response!"

    # 4. GET /anomalies
    print("[Testing 4/6] GET /anomalies")
    anom_res, anom_data = test_endpoint("GET /anomalies", "GET", "/anomalies?page=1&limit=10")
    assert anom_res.status_code == 200, "GET /anomalies failed!"
    assert anom_data.get("total") == 1207, f"Anomalies total mismatch: {anom_data.get('total')}"
    assert len(anom_data.get("anomalies", [])) == 10, "Anomalies pagination mismatch!"

    # 5. GET /model-performance
    print("[Testing 5/6] GET /model-performance")
    perf_res, perf_data = test_endpoint("GET /model-performance", "GET", "/model-performance")
    assert perf_res.status_code == 200, "GET /model-performance failed!"
    assert perf_data.get("total_events") == 1800, "Model total_events mismatch!"
    assert perf_data.get("anomaly_percentage") == 67.06, "Anomaly percentage mismatch!"

    # 6. GET /threat-summary
    print("[Testing 6/6] GET /threat-summary")
    sum_res, sum_data = test_endpoint("GET /threat-summary", "GET", "/threat-summary")
    assert sum_res.status_code == 200, "GET /threat-summary failed!"
    assert sum_data.get("total_predictions") == 1800, "Summary total_predictions mismatch!"
    assert sum_data.get("normal") == 593, "Summary normal mismatch!"
    assert sum_data.get("anomalous") == 1207, "Summary anomalous mismatch!"
    assert sum_data.get("threat_types", {}).get("Brute Force") == 429, "Brute force summary count mismatch!"

    # M1 APIs re-test
    print("\n[M1 Regression Tests]")
    m1_events_res, _ = test_endpoint("GET /events", "GET", "/events")
    m1_stats_res, _ = test_endpoint("GET /stats", "GET", "/stats")
    m1_threats_res, _ = test_endpoint("GET /threats", "GET", "/threats")
    assert m1_events_res.status_code == 200, "M1 /events failed!"
    assert m1_stats_res.status_code == 200, "M1 /stats failed!"
    assert m1_threats_res.status_code == 200, "M1 /threats failed!"

    # Print Summary Table
    print("\n" + "=" * 70)
    print("M2 & M1 API VERIFICATION TABLE")
    print("=" * 70)
    df_results = pd.DataFrame(api_results)
    print(df_results.to_string(index=False))

    # Data Integrity Verification
    db = SessionLocal()
    try:
        db_preds_count = db.query(ThreatPrediction).count()
        db_events_count = db.query(SecurityEvent).count()

        dup_count = db_preds_count - db.query(ThreatPrediction.event_id).distinct().count()
        
        event_ids_sec = set(r[0] for r in db.query(SecurityEvent.event_id).all())
        event_ids_pred = set(r[0] for r in db.query(ThreatPrediction.event_id).all())
        orphans_count = len(event_ids_pred - event_ids_sec)

        print("\n" + "=" * 70)
        print("DATA INTEGRITY VERIFICATION")
        print("=" * 70)
        print(f"Prediction count:     {db_preds_count}")
        print(f"Duplicate predictions:{dup_count}")
        print(f"Orphan predictions:   {orphans_count}")

        assert db_preds_count == 1800, f"Expected 1800 predictions, got {db_preds_count}"
        assert dup_count == 0, f"Found {dup_count} duplicate predictions!"
        assert orphans_count == 0, f"Found {orphans_count} orphan predictions!"

    finally:
        db.close()

    print("\n" + "=" * 70)
    print("ALL M2 REST API TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_api_tests()
