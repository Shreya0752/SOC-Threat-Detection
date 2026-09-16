"""
Prediction Repository Module for Milestone 3 (`backend/database/prediction_repository.py`).
Abstracts database access to M2 ThreatPrediction and M1 SecurityEvent records
stored in the primary SQLite database.
"""
import os
import sys
from typing import Optional, List, Dict, Any

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.database.db import SessionLocal
from backend.models.database_models import SecurityEvent, ThreatPrediction

class PredictionRepository:
    """Provides structured data access to M2 predictions and underlying security events."""

    @staticmethod
    def get_event_with_prediction(event_id: str, db=None) -> Optional[Dict[str, Any]]:
        """Retrieves a security event joined with its M2 prediction record."""
        should_close = False
        if db is None:
            db = SessionLocal()
            should_close = True

        try:
            event = db.query(SecurityEvent).filter(SecurityEvent.event_id == str(event_id)).first()
            if not event:
                return None

            prediction = db.query(ThreatPrediction).filter(ThreatPrediction.event_id == str(event_id)).first()
            
            event_dict = event.to_dict()
            if prediction:
                pred_dict = prediction.to_dict()
                event_dict["m2_prediction"] = pred_dict["prediction"]
                event_dict["m2_threat_type"] = pred_dict["threat_type"]
                event_dict["confidence_score"] = pred_dict["confidence_score"]
                event_dict["anomaly_score"] = pred_dict["anomaly_score"]
                event_dict["m2_severity"] = pred_dict["severity"]
                event_dict["m2_explanation"] = pred_dict["explanation"]
            else:
                # Default baseline if M2 prediction hasn't run yet
                event_dict["m2_prediction"] = "Normal" if event.severity == "Low" else "Anomalous"
                event_dict["m2_threat_type"] = event.event_type or "Unknown"
                event_dict["confidence_score"] = 50.0
                event_dict["anomaly_score"] = 0.0
                event_dict["m2_severity"] = event.severity or "Low"
                event_dict["m2_explanation"] = []

            return event_dict
        finally:
            if should_close:
                db.close()

    @staticmethod
    def get_all_events_for_correlation(db=None) -> List[Dict[str, Any]]:
        """
        Retrieves all security events joined with their M2 threat predictions,
        ordered by timestamp ascending for chronological correlation analysis.
        """
        should_close = False
        if db is None:
            db = SessionLocal()
            should_close = True

        try:
            # Query joined records
            query = db.query(SecurityEvent, ThreatPrediction)\
                      .outerjoin(ThreatPrediction, SecurityEvent.event_id == ThreatPrediction.event_id)\
                      .order_by(SecurityEvent.timestamp.asc())

            records = query.all()
            results = []
            for event, pred in records:
                evt_dict = event.to_dict()
                if pred:
                    pred_dict = pred.to_dict()
                    evt_dict["m2_prediction"] = pred_dict["prediction"]
                    evt_dict["m2_threat_type"] = pred_dict["threat_type"]
                    evt_dict["confidence_score"] = pred_dict["confidence_score"]
                    evt_dict["anomaly_score"] = pred_dict["anomaly_score"]
                    evt_dict["m2_severity"] = pred_dict["severity"]
                    evt_dict["m2_explanation"] = pred_dict["explanation"]
                else:
                    evt_dict["m2_prediction"] = "Normal" if event.severity == "Low" else "Anomalous"
                    evt_dict["m2_threat_type"] = event.event_type or "Unknown"
                    evt_dict["confidence_score"] = 50.0
                    evt_dict["anomaly_score"] = 0.0
                    evt_dict["m2_severity"] = event.severity or "Low"
                    evt_dict["m2_explanation"] = []
                results.append(evt_dict)

            return results
        finally:
            if should_close:
                db.close()
