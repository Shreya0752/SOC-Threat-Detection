"""
Milestone 2 Analytics Routes (`backend/routes/analytics_routes.py`).
Provides Flask blueprint endpoints for model evaluation metrics and threat summaries as specified in Milestone-2.md.
"""
import os
import sys
from flask import Blueprint, jsonify
from backend.routes.api import login_required
from backend.services.prediction_service import PredictionService

analytics_bp = Blueprint("analytics_routes", __name__)

@analytics_bp.route("/model-performance", methods=["GET"])
@login_required
def get_model_performance():
    """
    GET /model-performance
    Returns Isolation Forest performance evaluation metrics (Precision, Recall, F1, Confusion Matrix).
    """
    metrics = PredictionService.get_model_performance()
    return jsonify(metrics), 200

@analytics_bp.route("/threat-summary", methods=["GET"])
@login_required
def get_threat_summary():
    """
    GET /threat-summary
    Returns aggregated Milestone 2 threat detection summary statistics.
    """
    summary = PredictionService.get_threat_summary()
    return jsonify(summary), 200
