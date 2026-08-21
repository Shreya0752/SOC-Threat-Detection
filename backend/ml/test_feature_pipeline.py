"""
Verification Test Script for M2 Feature Pipeline.
Executes against the live SQLite database, extracts M2 features, runs scikit-learn preprocessing,
validates zero missing/inf values, and confirms database integrity.
"""
import os
import sys
import numpy as np
import pandas as pd

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database.db import engine, SessionLocal, init_db
from backend.models.database_models import SecurityEvent, ThreatPrediction, User, CleaningStats
from backend.ml.feature_selection import load_m1_events_from_db, extract_features
from backend.ml.preprocessing import ThreatDataPreprocessor

def run_verification():
    print("=" * 70)
    print("MILESTONE 2 - STEP 1 VERIFICATION & DATA VALIDATION")
    print("=" * 70)

    # 1. Ensure database tables exist (safely adds threat_predictions if missing)
    init_db(force_reseed=False)
    
    db = SessionLocal()
    try:
        total_m1_events = db.query(SecurityEvent).count()
        print(f"[DB Verification] M1 Security Events in SQLite: {total_m1_events}")
        assert total_m1_events > 0, "No security events found in database!"
        
        # Verify ThreatPrediction table exists
        prediction_count = db.query(ThreatPrediction).count()
        print(f"[DB Verification] ThreatPrediction table exists. Current prediction rows: {prediction_count}")
    finally:
        db.close()

    # 2. Load M1 events from DB & Extract Features
    print("\n[Step 2] Feature Selection & Extraction")
    print("-" * 70)
    df_events = load_m1_events_from_db()
    event_ids, X_raw = extract_features(df_events)
    
    print(f"Input security events: {len(df_events)}")
    print(f"Preserved event_ids count: {len(event_ids)}")
    print(f"Raw feature matrix shape: {X_raw.shape}")
    print(f"Raw feature columns: {list(X_raw.columns)}")
    
    # Missing values before preprocessing
    null_before = int(X_raw.isnull().sum().sum())
    print(f"Missing values before preprocessing: {null_before}")
    print("\nRaw Features Data Types:")
    print(X_raw.dtypes)

    # 3. Preprocessing
    print("\n[Step 3] Scikit-Learn Preprocessing (Imputation + Scaling + OneHot)")
    print("-" * 70)
    preprocessor = ThreatDataPreprocessor()
    X_processed = preprocessor.fit_transform(X_raw)
    feature_names = preprocessor.get_feature_names()

    null_after = int(np.isnan(X_processed).sum())
    inf_after = int(np.isinf(X_processed).sum())

    print(f"Encoded feature count: {len(feature_names)}")
    print(f"Final feature names: {feature_names}")
    print(f"Missing values after preprocessing: {null_after}")
    print(f"Infinity values after preprocessing: {inf_after}")
    print(f"Final processed matrix shape: {X_processed.shape}")

    # Assertions
    assert len(df_events) == len(event_ids), "Event ID count mismatch!"
    assert X_processed.shape[0] == len(df_events), "Row count changed after preprocessing!"
    assert null_after == 0, "NaN values present in final matrix!"
    assert inf_after == 0, "Inf values present in final matrix!"

    print("\n" + "=" * 70)
    print("VERIFICATION SUCCESSFUL: ALL STEP 1 CHECKS PASSED")
    print("=" * 70)

if __name__ == "__main__":
    run_verification()
