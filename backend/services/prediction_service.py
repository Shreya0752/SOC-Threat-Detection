"""
Prediction Service Module for Milestone 2.
Provides database access and model execution methods for prediction endpoints:
- Single event prediction (POST /predict)
- Paginated predictions retrieval (GET /predictions)
- Event prediction lookup (GET /predictions/{event_id})
- Anomalies listing (GET /anomalies)
- Unsupervised model performance metrics (GET /model-performance)
- Threat summary aggregations (GET /threat-summary)
"""
import os
import sys
import json
from datetime import datetime, timezone
import numpy as np
import pandas as pd
from sqlalchemy import func, or_

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.models.database_models import SecurityEvent, ThreatPrediction
from backend.ml.feature_selection import extract_features
from backend.ml.model_loader import load_model, load_preprocessor
from backend.ml.threat_classification import classify_event, MODEL_VERSION

class PredictionService:
    
    @staticmethod
    def predict_single_event(db, event_id_or_payload):
        """
        Executes prediction pipeline for a single event_id or raw event dict using saved ML artifacts.
        Updates or inserts prediction into threat_predictions table idempotently.
        """
        if isinstance(event_id_or_payload, dict):
            payload = event_id_or_payload
            event_id = payload.get("event_id") or f"EVT_LIVE_{int(datetime.now().timestamp())}"
            event_dict = {
                "event_id": event_id,
                "timestamp": payload.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
                "severity": payload.get("severity", "Medium"),
                "status": payload.get("status", "Detected"),
                "source_ip": payload.get("source_ip", "127.0.0.1"),
                "destination_ip": payload.get("destination_ip", "10.0.0.1"),
                "username": payload.get("username", "analyst_admin"),
                "device_name": payload.get("device_name", "Device-Live"),
                "event_type": payload.get("event_type", "Unknown"),
                "failed_login_attempts": payload.get("failed_login_attempts", 0),
                "cvss_score": payload.get("cvss_score", 0.0),
                "malware_detected": payload.get("malware_detected", "No")
            }
            for k, v in payload.items():
                event_dict[k] = v
        else:
            event_id = str(event_id_or_payload)
            event = db.query(SecurityEvent).filter(SecurityEvent.event_id == event_id).first()
            if not event:
                return None
            event_dict = event.to_dict()

        df_event = pd.DataFrame([event_dict])
        if "engineered_features" in df_event.columns:
            eng_df = pd.json_normalize(df_event["engineered_features"])
            for col in eng_df.columns:
                if col not in df_event.columns or df_event[col].isnull().all():
                    df_event[col] = eng_df[col]

        _, X_raw = extract_features(df_event)

        # Load saved model & preprocessor artifacts (no retraining)
        model = load_model()
        preprocessor = load_preprocessor()

        X_processed = preprocessor.transform(X_raw)
        raw_pred = model.predict(X_processed)[0]
        prediction_label = "Normal" if raw_pred == 1 else "Anomalous"
        anomaly_score = float(model.decision_function(X_processed)[0])

        classified = classify_event(df_event.iloc[0], prediction_label, anomaly_score)
        current_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        explanation_json = json.dumps(classified["reasons"])

        # Check existing record
        pred_obj = db.query(ThreatPrediction).filter(ThreatPrediction.event_id == event_id).first()
        if pred_obj:
            pred_obj.prediction = classified["prediction"]
            pred_obj.threat_type = classified["threat_type"]
            pred_obj.confidence_score = classified["confidence_score"]
            pred_obj.anomaly_score = classified["anomaly_score"]
            pred_obj.severity = classified["severity"]
            pred_obj.model_version = MODEL_VERSION
            pred_obj.prediction_timestamp = current_timestamp
            pred_obj.explanation = explanation_json
            db.commit()
            db.refresh(pred_obj)
            return pred_obj.to_dict()
        else:
            # Check if event_id exists in SecurityEvent table
            sec_evt = db.query(SecurityEvent).filter(SecurityEvent.event_id == event_id).first()
            if sec_evt:
                pred_obj = ThreatPrediction(
                    event_id=event_id,
                    prediction=classified["prediction"],
                    threat_type=classified["threat_type"],
                    confidence_score=classified["confidence_score"],
                    anomaly_score=classified["anomaly_score"],
                    severity=classified["severity"],
                    model_version=MODEL_VERSION,
                    prediction_timestamp=current_timestamp,
                    explanation=explanation_json
                )
                db.add(pred_obj)
                db.commit()
                db.refresh(pred_obj)
                return pred_obj.to_dict()
            else:
                # Live custom payload test - return result dictionary directly without persisting extra non-M1 DB rows
                return {
                    "event_id": event_id,
                    "prediction": classified["prediction"],
                    "threat_type": classified["threat_type"],
                    "confidence_score": classified["confidence_score"],
                    "anomaly_score": classified["anomaly_score"],
                    "severity": classified["severity"],
                    "model_version": MODEL_VERSION,
                    "prediction_timestamp": current_timestamp,
                    "explanation": classified["reasons"]
                }

    @staticmethod
    def get_predictions(db, page=1, limit=25, prediction=None, threat_type=None, severity=None, search=None):
        """
        Retrieves paginated and filtered prediction records from threat_predictions table.
        """
        query = db.query(ThreatPrediction)

        if prediction and prediction.lower() != "all":
            query = query.filter(func.lower(ThreatPrediction.prediction) == prediction.lower())

        if threat_type and threat_type.lower() != "all":
            query = query.filter(func.lower(ThreatPrediction.threat_type) == threat_type.lower())

        if severity and severity.lower() != "all":
            query = query.filter(func.lower(ThreatPrediction.severity) == severity.lower())

        if search and search.strip():
            search_pattern = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    func.lower(ThreatPrediction.event_id).like(func.lower(search_pattern)),
                    func.lower(ThreatPrediction.threat_type).like(func.lower(search_pattern)),
                    func.lower(ThreatPrediction.prediction).like(func.lower(search_pattern))
                )
            )

        total_count = query.count()
        query = query.order_by(ThreatPrediction.id.asc())

        if limit > 0:
            offset = (page - 1) * limit
            records = query.offset(offset).limit(limit).all()
        else:
            records = query.all()

        return {
            "total": total_count,
            "page": page,
            "limit": limit,
            "predictions": [p.to_dict() for p in records]
        }

    @staticmethod
    def get_prediction_by_event_id(db, event_id):
        """
        Retrieves prediction for a specific event_id.
        """
        record = db.query(ThreatPrediction).filter(ThreatPrediction.event_id == event_id).first()
        if not record:
            return None
        return record.to_dict()

    @staticmethod
    def get_anomalies(db, page=1, limit=25):
        """
        Retrieves paginated anomalous event predictions joined with event timestamp.
        """
        query = db.query(ThreatPrediction, SecurityEvent.timestamp.label("event_timestamp"))\
                  .join(SecurityEvent, ThreatPrediction.event_id == SecurityEvent.event_id)\
                  .filter(func.lower(ThreatPrediction.prediction) == "anomalous")

        total_count = query.count()
        query = query.order_by(ThreatPrediction.id.asc())

        if limit > 0:
            offset = (page - 1) * limit
            records = query.offset(offset).limit(limit).all()
        else:
            records = query.all()

        results = []
        for pred, evt_time in records:
            d = pred.to_dict()
            d["event_timestamp"] = evt_time
            results.append(d)

        return {
            "total": total_count,
            "page": page,
            "limit": limit,
            "anomalies": results
        }

    @staticmethod
    def get_model_performance(db):
        """
        Computes dynamic unsupervised model performance metrics.
        """
        total_events = db.query(ThreatPrediction).count()
        normal_events = db.query(ThreatPrediction).filter(func.lower(ThreatPrediction.prediction) == "normal").count()
        anomalous_events = db.query(ThreatPrediction).filter(func.lower(ThreatPrediction.prediction) == "anomalous").count()

        anomaly_pct = round((anomalous_events / total_events) * 100, 2) if total_events > 0 else 0.0

        scores = [p.anomaly_score for p in db.query(ThreatPrediction.anomaly_score).all()]
        if scores:
            min_score = float(np.min(scores))
            max_score = float(np.max(scores))
            mean_score = float(np.mean(scores))
            median_score = float(np.median(scores))
        else:
            min_score = max_score = mean_score = median_score = 0.0

        # Read hyperparams from loaded model
        try:
            model = load_model()
            n_estimators = model.n_estimators
            random_state = model.random_state
        except Exception:
            n_estimators = 200
            random_state = 42

        return {
            "model_name": "Isolation Forest",
            "model_type": "Unsupervised Anomaly Detection",
            "model_version": MODEL_VERSION,
            "total_events": total_events,
            "normal_events": normal_events,
            "anomalous_events": anomalous_events,
            "anomaly_percentage": anomaly_pct,
            "minimum_anomaly_score": round(min_score, 4),
            "maximum_anomaly_score": round(max_score, 4),
            "mean_anomaly_score": round(mean_score, 4),
            "median_anomaly_score": round(median_score, 4),
            "n_estimators": n_estimators,
            "random_state": random_state,
            "evaluation_note": "Unsupervised Isolation Forest anomaly detection evaluated on unlabeled security event baseline. Labeled supervised metrics (Precision/Recall/F1) require ground-truth analyst incident labels."
        }

    @staticmethod
    def get_threat_summary(db):
        """
        Computes dynamic threat summary statistics from threat_predictions database table.
        """
        total_preds = db.query(ThreatPrediction).count()
        normal_cnt = db.query(ThreatPrediction).filter(func.lower(ThreatPrediction.prediction) == "normal").count()
        anom_cnt = db.query(ThreatPrediction).filter(func.lower(ThreatPrediction.prediction) == "anomalous").count()

        anomaly_pct = round((anom_cnt / total_preds) * 100, 2) if total_preds > 0 else 0.0

        # Threat types distribution
        tt_query = db.query(ThreatPrediction.threat_type, func.count(ThreatPrediction.id))\
                     .group_by(ThreatPrediction.threat_type)\
                     .order_by(func.count(ThreatPrediction.id).desc()).all()
        threat_types = {tt: cnt for tt, cnt in tt_query}

        # Threat levels distribution
        sev_query = db.query(ThreatPrediction.severity, func.count(ThreatPrediction.id))\
                      .group_by(ThreatPrediction.severity).all()
        threat_levels_dict = {sev: cnt for sev, cnt in sev_query}
        threat_levels = {
            "Low": threat_levels_dict.get("Low", 0),
            "Medium": threat_levels_dict.get("Medium", 0),
            "High": threat_levels_dict.get("High", 0),
            "Critical": threat_levels_dict.get("Critical", 0)
        }

        # Confidence stats
        conf_scores = [p.confidence_score for p in db.query(ThreatPrediction.confidence_score).all()]
        if conf_scores:
            conf_min = round(float(np.min(conf_scores)), 1)
            conf_max = round(float(np.max(conf_scores)), 1)
            conf_mean = round(float(np.mean(conf_scores)), 1)
            conf_median = round(float(np.median(conf_scores)), 1)
        else:
            conf_min = conf_max = conf_mean = conf_median = 0.0

        return {
            "total_predictions": total_preds,
            "normal": normal_cnt,
            "anomalous": anom_cnt,
            "anomaly_percentage": anomaly_pct,
            "threat_types": threat_types,
            "threat_levels": threat_levels,
            "confidence": {
                "min": conf_min,
                "max": conf_max,
                "mean": conf_mean,
                "median": conf_median
            }
        }
