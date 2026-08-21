"""
Milestone 2 Anomaly Routes (`backend/routes/anomaly_routes.py`).
Provides Flask blueprint endpoints for anomaly predictions as specified in Milestone-2.md.
"""
import os
import sys
from flask import Blueprint, request, jsonify
from backend.routes.api import login_required
from backend.services.prediction_service import PredictionService

anomaly_bp = Blueprint("anomaly_routes", __name__)

@anomaly_bp.route("/anomalies", methods=["GET"])
@login_required
def get_anomalies():
    """
    GET /anomalies
    Retrieves filtered list of detected anomalous security events.
    """
    severity = request.args.get("severity")
    limit = int(request.args.get("limit", 100))
    data = PredictionService.get_anomalies(severity=severity, limit=limit)
    return jsonify(data), 200

@anomaly_bp.route("/predict", methods=["POST"])
@login_required
def predict_single():
    """
    POST /predict
    Submits a security event for real-time anomaly detection prediction.
    """
    payload = request.get_json(silent=True) or {}
    event_id = payload.get("event_id")
    result = PredictionService.predict_single_event(payload, event_id=event_id)
    if "error" in result and not result.get("prediction"):
        return jsonify(result), 400
    return jsonify(result), 200
