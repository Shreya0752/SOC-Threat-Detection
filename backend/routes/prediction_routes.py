"""
Prediction Routes Blueprint for Milestone 2.
Exposes M2 REST API endpoints:
- POST /predict
- GET /predictions
- GET /predictions/{event_id}
- GET /anomalies
- GET /model-performance
- GET /threat-summary
"""
import os
import sys
from flask import Blueprint, request, jsonify
from backend.database.db import SessionLocal
from backend.routes.api import login_required
from backend.services.prediction_service import PredictionService

pred_bp = Blueprint("prediction_routes", __name__)

def db_session():
    return SessionLocal()

@pred_bp.route("/predict", methods=["POST"])
@login_required
def predict_event():
    data = request.get_json(silent=True) or {}
    event_id = str(data.get("event_id") or request.args.get("event_id") or "").strip()

    db = db_session()
    try:
        if event_id:
            result = PredictionService.predict_single_event(db, event_id)
        else:
            result = PredictionService.predict_single_event(db, data)
            
        if not result:
            return jsonify({"error": f"Security event not found or invalid payload"}), 404
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred during prediction: {str(e)}"}), 500
    finally:
        db.close()

@pred_bp.route("/predictions", methods=["GET"])
@login_required
def get_predictions():
    db = db_session()
    try:
        prediction = request.args.get("prediction")
        threat_type = request.args.get("threat_type")
        severity = request.args.get("severity")
        search = request.args.get("search")

        try:
            page = int(request.args.get("page", 1))
        except ValueError:
            page = 1

        try:
            limit = int(request.args.get("limit", 25))
        except ValueError:
            limit = 25

        data = PredictionService.get_predictions(
            db=db,
            page=page,
            limit=limit,
            prediction=prediction,
            threat_type=threat_type,
            severity=severity,
            search=search
        )
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@pred_bp.route("/predictions/<path:event_id>", methods=["GET"])
@login_required
def get_prediction_by_id(event_id):
    event_id_clean = str(event_id).strip()
    db = db_session()
    try:
        result = PredictionService.get_prediction_by_event_id(db, event_id_clean)
        if not result:
            return jsonify({"error": f"Prediction not found for event_id: {event_id_clean}"}), 404
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@pred_bp.route("/anomalies", methods=["GET"])
@login_required
def get_anomalies():
    db = db_session()
    try:
        try:
            page = int(request.args.get("page", 1))
        except ValueError:
            page = 1

        try:
            limit = int(request.args.get("limit", 25))
        except ValueError:
            limit = 25

        data = PredictionService.get_anomalies(db, page=page, limit=limit)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@pred_bp.route("/model-performance", methods=["GET"])
@login_required
def get_model_performance():
    db = db_session()
    try:
        data = PredictionService.get_model_performance(db)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@pred_bp.route("/threat-summary", methods=["GET"])
@login_required
def get_threat_summary():
    db = db_session()
    try:
        data = PredictionService.get_threat_summary(db)
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()
