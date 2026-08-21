import os
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.ml.feature_selection import load_m1_events_from_db, extract_features
from backend.ml.preprocessing import ThreatDataPreprocessor
from backend.ml.model_loader import save_model, load_model, save_preprocessor, load_preprocessor

class AnomalyDetector:
    """
    Isolation Forest wrapper for cybersecurity anomaly detection.
    """
    def __init__(self, n_estimators=200, contamination="auto", random_state=42):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.is_fitted = False

    def fit(self, X_processed):
        """
        Fits Isolation Forest model on scaled/encoded numerical matrix.
        """
        self.model.fit(X_processed)
        self.is_fitted = True
        return self

    def predict(self, X_processed):
        """
        Generates predictions for feature matrix.
        Returns array of strings: 'Normal' (1) or 'Anomalous' (-1).
        """
        if not self.is_fitted:
            raise ValueError("Isolation Forest model must be fitted before predicting.")

        raw_preds = self.model.predict(X_processed)
        # Convert 1 -> 'Normal', -1 -> 'Anomalous'
        labels = np.where(raw_preds == 1, "Normal", "Anomalous")
        return labels

    def compute_anomaly_scores(self, X_processed):
        """
        Computes raw decision_function anomaly scores.
        Note: Lower/negative scores indicate higher degree of anomaly.
        """
        if not self.is_fitted:
            raise ValueError("Isolation Forest model must be fitted before computing anomaly scores.")

        scores = self.model.decision_function(X_processed)
        return scores

def train_isolation_forest_pipeline(save_artifacts=True):
    """
    Complete end-to-end training pipeline for Step 2.
    1. Loads M1 events from SQLite database
    2. Extracts M2 raw feature matrix (X_raw) and event_ids
    3. Fits ThreatDataPreprocessor on X_raw
    4. Fits IsolationForest on X_processed
    5. Generates predictions and raw decision_function scores
    6. Saves model and preprocessor artifacts to disk
    
    Returns:
        detector (AnomalyDetector)
        preprocessor (ThreatDataPreprocessor)
        results_df (pd.DataFrame) with event_id, prediction, anomaly_score
    """
    print("[Training Pipeline] Loading M1 security events from SQLite...")
    df_events = load_m1_events_from_db()
    event_ids, X_raw = extract_features(df_events)

    print("[Training Pipeline] Preprocessing features with ThreatDataPreprocessor...")
    preprocessor = ThreatDataPreprocessor()
    X_processed = preprocessor.fit_transform(X_raw)

    print(f"[Training Pipeline] Training IsolationForest (n_estimators=200, random_state=42) on {X_processed.shape} matrix...")
    detector = AnomalyDetector(n_estimators=200, contamination="auto", random_state=42)
    detector.fit(X_processed)

    print("[Training Pipeline] Generating predictions and raw decision scores...")
    predictions = detector.predict(X_processed)
    anomaly_scores = detector.compute_anomaly_scores(X_processed)

    results_df = pd.DataFrame({
        "event_id": event_ids,
        "prediction": predictions,
        "anomaly_score": anomaly_scores
    })

    if save_artifacts:
        save_model(detector.model)
        save_preprocessor(preprocessor)

    return detector, preprocessor, results_df

if __name__ == "__main__":
    detector, preprocessor, results_df = train_isolation_forest_pipeline(save_artifacts=True)
    
    total = len(results_df)
    normal_cnt = (results_df["prediction"] == "Normal").sum()
    anom_cnt = (results_df["prediction"] == "Anomalous").sum()
    anom_pct = round((anom_cnt / total) * 100, 2)

    print("\n" + "=" * 50)
    print("ISOLATION FOREST TRAINING SUMMARY")
    print("=" * 50)
    print(f"Total events processed: {total}")
    print(f"Normal events:          {normal_cnt}")
    print(f"Anomalous events:       {anom_cnt} ({anom_pct}%)")
    print(f"Min Anomaly Score:      {results_df['anomaly_score'].min():.4f}")
    print(f"Max Anomaly Score:      {results_df['anomaly_score'].max():.4f}")
    print(f"Mean Anomaly Score:     {results_df['anomaly_score'].mean():.4f}")
    print(f"Median Anomaly Score:   {results_df['anomaly_score'].median():.4f}")
    print("=" * 50)
