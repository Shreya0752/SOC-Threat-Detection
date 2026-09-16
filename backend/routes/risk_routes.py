"""
Risk Routes Blueprint for Milestone 3 (`backend/routes/risk_routes.py`).
Exposes M3 REST API endpoints:
- POST /api/v1/risk/calculate
- GET /api/v1/risk/high
- GET /api/v1/risk/summary
"""
import os
import sys
from flask import Blueprint, request, jsonify

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.routes.api import login_required
from backend.services.risk_service import RiskService

risk_bp = Blueprint("risk_routes", __name__)

@risk_bp.route("/api/v1/risk/calculate", methods=["POST"])
@login_required
def calculate_risk():
    """
    POST /api/v1/risk/calculate
    Calculates transparent 0-100 weighted risk score for an event_id or event payload.
    """
    payload = request.get_json(silent=True) or {}
    try:
        result = RiskService.calculate_risk(payload)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Failed to calculate risk score: {str(e)}"}), 500

@risk_bp.route("/api/v1/risk/high", methods=["GET"])
@login_required
def get_high_risk():
    """
    GET /api/v1/risk/high
    Retrieves highest priority / critical risk threats for immediate analyst attention.
    """
    try:
        limit = int(request.args.get("limit", 25))
    except ValueError:
        limit = 25

    try:
        data = RiskService.get_high_risk_threats(limit=limit)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve high risk threats: {str(e)}"}), 500

@risk_bp.route("/api/v1/risk/summary", methods=["GET"])
@login_required
def get_risk_summary():
    """
    GET /api/v1/risk/summary
    Retrieves aggregated M3 risk telemetry (distribution, average score, storage status).
    """
    try:
        data = RiskService.get_risk_summary()
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve risk summary: {str(e)}"}), 500

@risk_bp.route("/api/v1/risk/weights", methods=["GET"])
@login_required
def get_risk_weights():
    """
    GET /api/v1/risk/weights
    Retrieves current active weights, default baseline weights, and validation status.
    """
    from backend.risk.risk_score import RiskScoreEngine, DEFAULT_RISK_WEIGHTS
    from backend.database.incident_repository import IncidentRepository

    persisted = IncidentRepository.get_risk_weights()
    if persisted:
        try:
            RiskScoreEngine.set_active_weights(persisted)
        except Exception:
            pass

    active = RiskScoreEngine.get_active_weights()
    w_sev = active.get("threat_severity", 0.25)
    w_conf = active.get("ml_confidence", 0.25)
    w_asset = active.get("asset_criticality", 0.20)
    w_vuln = active.get("vulnerability_exposure", 0.20)
    w_intel = active.get("threat_intelligence", 0.10)

    formula = (
        f"(Severity * {w_sev:.2f}) + (Confidence * {w_conf:.2f}) + "
        f"(Asset * {w_asset:.2f}) + (Vuln * {w_vuln:.2f}) + (Intel * {w_intel:.2f})"
    )

    return jsonify({
        "weights": active,
        "default_weights": DEFAULT_RISK_WEIGHTS,
        "is_default": active == DEFAULT_RISK_WEIGHTS,
        "formula": formula,
        "sum": round(sum(active.values()), 3)
    }), 200

@risk_bp.route("/api/v1/risk/weights", methods=["PUT", "POST"])
@login_required
def update_risk_weights():
    """
    PUT /api/v1/risk/weights
    Validates and updates custom risk factor weights (must sum to 1.0 / 100%).
    Optionally triggers recalculation of incident risk scores if recalculate=true.
    """
    from backend.risk.risk_score import RiskScoreEngine
    from backend.database.incident_repository import IncidentRepository
    from backend.services.incident_service import IncidentService

    payload = request.get_json(silent=True) or {}
    weights = payload.get("weights") or payload

    is_valid, msg = RiskScoreEngine.validate_weights(weights)
    if not is_valid:
        return jsonify({"error": msg, "weights": weights}), 400

    try:
        RiskScoreEngine.set_active_weights(weights)
        IncidentRepository.save_risk_weights(RiskScoreEngine.get_active_weights())

        recalculate = bool(payload.get("recalculate", False))
        recalc_result = None
        if recalculate:
            recalc_result = IncidentService.recalculate_all_incidents(RiskScoreEngine.get_active_weights())

        return jsonify({
            "message": "Risk weights updated successfully",
            "weights": RiskScoreEngine.get_active_weights(),
            "recalculated": recalculate,
            "recalculation_summary": recalc_result
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to save risk weights: {str(e)}"}), 500

@risk_bp.route("/api/v1/risk/weights/reset", methods=["POST"])
@login_required
def reset_risk_weights():
    """
    POST /api/v1/risk/weights/reset
    Resets weights to standard documented configuration:
    Severity: 0.25, Confidence: 0.25, Asset: 0.20, Vuln: 0.20, Intel: 0.10.
    """
    from backend.risk.risk_score import RiskScoreEngine, DEFAULT_RISK_WEIGHTS
    from backend.database.incident_repository import IncidentRepository
    from backend.services.incident_service import IncidentService

    try:
        reset_w = RiskScoreEngine.reset_active_weights()
        IncidentRepository.save_risk_weights(reset_w)

        payload = request.get_json(silent=True) or {}
        recalculate = bool(payload.get("recalculate", False))
        recalc_result = None
        if recalculate:
            recalc_result = IncidentService.recalculate_all_incidents(reset_w)

        return jsonify({
            "message": "Risk weights reset to default documented baseline",
            "weights": reset_w,
            "recalculated": recalculate,
            "recalculation_summary": recalc_result
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to reset weights: {str(e)}"}), 500

@risk_bp.route("/api/v1/risk/recalculate", methods=["POST"])
@login_required
def recalculate_risk():
    """
    POST /api/v1/risk/recalculate
    Triggers re-scoring of all persisted incidents using current active weights.
    """
    from backend.services.incident_service import IncidentService
    try:
        summary = IncidentService.recalculate_all_incidents()
        return jsonify({
            "message": f"Successfully recalculated {summary.get('updated_count', 0)} incidents",
            "summary": summary
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to recalculate incident scores: {str(e)}"}), 500

