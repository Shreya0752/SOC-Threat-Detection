"""
Milestone 2 Scoring Service (`backend/services/scoring_service.py`).
Provides threat confidence scoring, risk level calculations, and anomaly
score calibrations as specified in Milestone-2.md.
"""
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

class ScoringService:
    @staticmethod
    def calculate_confidence_score(anomaly_score, severity_score, failed_login_attempts=0, malware_detected=False, impossible_travel=False):
        """
        Calculates calibrated confidence score (0.0 to 100.0) based on Isolation Forest
        anomaly score, M1 severity score, and threat indicators.
        """
        # Base confidence from anomaly score offset
        base_confidence = max(0.0, (0.5 - anomaly_score) * 100.0)
        
        # Severity weighting
        sev_weight = min(40.0, float(severity_score) * 10.0)
        
        # Threat indicator boosts
        brute_force_boost = min(25.0, (failed_login_attempts / 10.0) * 15.0) if failed_login_attempts > 0 else 0.0
        malware_boost = 25.0 if malware_detected else 0.0
        travel_boost = 20.0 if impossible_travel else 0.0
        
        total_score = base_confidence * 0.4 + sev_weight + brute_force_boost + malware_boost + travel_boost
        return round(min(100.0, max(0.0, total_score)), 2)

    @staticmethod
    def determine_threat_severity(confidence_score, prediction_label):
        """
        Maps confidence score and prediction label to standardized threat severity.
        """
        if prediction_label != "Anomalous":
            return "Low"
        
        if confidence_score >= 85.0:
            return "Critical"
        elif confidence_score >= 70.0:
            return "High"
        elif confidence_score >= 50.0:
            return "Medium"
        else:
            return "Low"
