"""
Milestone 2 Threat Classifier Module (`backend/ml/classifier.py`).
Implements supervised/rule-assisted threat classification, confidence scoring,
and explainability reasoning as specified in Milestone-2.md.
"""
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.ml.threat_classification import (
    classify_event,
    classify_and_score_all_events,
    run_threat_classification_pipeline
)

class ThreatClassifier:
    """
    Threat Classification interface wrapper for Milestone 2 ML pipeline.
    """
    @staticmethod
    def classify(event_row, prediction_label, anomaly_score):
        return classify_event(event_row, prediction_label, anomaly_score)

    @staticmethod
    def process_all(db_session=None):
        return run_threat_classification_pipeline(db_session)
