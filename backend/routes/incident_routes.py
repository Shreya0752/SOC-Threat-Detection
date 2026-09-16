"""
Incident Routes Blueprint for Milestone 3 (`backend/routes/incident_routes.py`).
Exposes M3 REST API endpoints:
- GET   /api/v1/incidents
- GET   /api/v1/incidents/{incident_id}
- GET   /api/v1/attack-chains
- GET   /api/v1/recommendations/{incident_id}
- PATCH /api/v1/incidents/{incident_id}/status
"""
import os
import sys
from flask import Blueprint, request, jsonify

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.routes.api import login_required
from backend.services.incident_service import IncidentService

incident_bp = Blueprint("incident_routes", __name__)

@incident_bp.route("/api/v1/incidents", methods=["GET"])
@login_required
def get_incidents():
    """
    GET /api/v1/incidents
    Retrieves filtered, paginated incidents sorted dynamically by descending risk score
    or custom sort criteria with multi-field filtering.
    """
    priority = request.args.get("priority")
    threat_type = request.args.get("threat_type")
    asset_id = request.args.get("asset_id") or request.args.get("asset")
    department = request.args.get("department")
    mitre_technique = request.args.get("mitre_technique")
    ioc_status = request.args.get("ioc_status")
    status = request.args.get("status")
    search = request.args.get("search")
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    sort_by = request.args.get("sort_by", "risk_score")
    sort_order = request.args.get("sort_order", "desc")

    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        page = 1

    try:
        limit = int(request.args.get("limit", 25))
    except ValueError:
        limit = 25

    try:
        data = IncidentService.get_incidents(
            priority=priority,
            threat_type=threat_type,
            asset_id=asset_id,
            department=department,
            mitre_technique=mitre_technique,
            ioc_status=ioc_status,
            status=status,
            search=search,
            date_from=date_from,
            date_to=date_to,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            limit=limit
        )
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve incidents: {str(e)}"}), 500

@incident_bp.route("/api/v1/incidents/<incident_id>", methods=["GET"])
@login_required
def get_incident_by_id(incident_id):
    """
    GET /api/v1/incidents/{incident_id}
    Retrieves complete details for a single incident including contributing events.
    """
    clean_id = str(incident_id).strip()
    try:
        incident = IncidentService.get_incident_by_id(clean_id)
        if not incident:
            return jsonify({"error": f"Incident not found: {clean_id}"}), 404
        return jsonify(incident), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve incident {clean_id}: {str(e)}"}), 500

@incident_bp.route("/api/v1/incidents/<incident_id>/risk-comparison", methods=["GET"])
@login_required
def get_incident_risk_comparison(incident_id):
    """
    GET /api/v1/incidents/{incident_id}/risk-comparison
    Retrieves comparative analysis between isolated base score vs. correlated composite score.
    """
    clean_id = str(incident_id).strip()
    try:
        comparison = IncidentService.get_incident_risk_comparison(clean_id)
        if not comparison:
            return jsonify({"error": f"Incident not found: {clean_id}"}), 404
        return jsonify(comparison), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve risk comparison for {clean_id}: {str(e)}"}), 500

@incident_bp.route("/api/v1/incidents/<incident_id>/timeline", methods=["GET"])
@login_required
def get_incident_timeline(incident_id):
    """
    GET /api/v1/incidents/{incident_id}/timeline
    Retrieves unified chronological investigation timeline (events, attack stages, status changes, feedback).
    """
    clean_id = str(incident_id).strip()
    try:
        timeline = IncidentService.get_incident_timeline(clean_id)
        if not timeline:
            return jsonify({"error": f"Incident not found: {clean_id}"}), 404
        return jsonify(timeline), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve timeline for {clean_id}: {str(e)}"}), 500

@incident_bp.route("/api/v1/incidents/<incident_id>/feedback", methods=["POST"])
@login_required
def submit_analyst_feedback(incident_id):
    """
    POST /api/v1/incidents/{incident_id}/feedback
    Records analyst feedback (True Positive, False Positive, Needs Review) with notes
    without modifying underlying ML model predictions.
    """
    clean_id = str(incident_id).strip()
    payload = request.get_json(silent=True) or {}
    feedback = payload.get("feedback")
    notes = payload.get("notes", "")
    analyst = payload.get("analyst", "SOC Analyst")

    if not feedback:
        return jsonify({"error": "Missing 'feedback' field in payload"}), 400

    valid_feedback = ["True Positive", "False Positive", "Needs Review"]
    if feedback not in valid_feedback:
        return jsonify({"error": f"Invalid feedback '{feedback}'. Allowed: {valid_feedback}"}), 400

    try:
        success = IncidentService.add_analyst_feedback(clean_id, feedback, notes=notes, analyst=analyst)
        if not success:
            return jsonify({"error": f"Incident not found: {clean_id}"}), 404
        return jsonify({
            "message": "Analyst feedback recorded successfully",
            "incident_id": clean_id,
            "feedback": feedback,
            "notes": notes,
            "analyst": analyst
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to record analyst feedback: {str(e)}"}), 500

@incident_bp.route("/api/v1/attack-chains", methods=["GET"])
@login_required
def get_attack_chains():
    """
    GET /api/v1/attack-chains
    Retrieves correlated multi-stage attack scenarios across all incidents.
    """
    try:
        chains = IncidentService.get_attack_chains()
        return jsonify({"total_attack_chains": len(chains), "attack_chains": chains}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve attack chains: {str(e)}"}), 500

@incident_bp.route("/api/v1/recommendations/<incident_id>", methods=["GET"])
@login_required
def get_recommendations(incident_id):
    """
    GET /api/v1/recommendations/{incident_id}
    Retrieves guidance-only response playbooks for the specified incident.
    """
    clean_id = str(incident_id).strip()
    try:
        data = IncidentService.get_recommendations_for_incident(clean_id)
        if not data:
            return jsonify({"error": f"Incident not found: {clean_id}"}), 404
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve recommendations: {str(e)}"}), 500

@incident_bp.route("/api/v1/incidents/<incident_id>/status", methods=["PATCH", "POST", "PUT"])
@login_required
def update_incident_status(incident_id):
    """
    PATCH / PUT /api/v1/incidents/{incident_id}/status
    Updates analyst investigation status: Open, Investigating, Resolved, False Positive.
    Logs transition in audit history.
    """
    clean_id = str(incident_id).strip()
    payload = request.get_json(silent=True) or {}
    new_status = payload.get("status")
    analyst = payload.get("analyst", "SOC Analyst")
    notes = payload.get("notes", "")

    if not new_status:
        return jsonify({"error": "Missing 'status' in request payload"}), 400

    valid_statuses = ["Open", "Investigating", "Resolved", "False Positive"]
    if new_status not in valid_statuses:
        return jsonify({"error": f"Invalid status '{new_status}'. Allowed values: {valid_statuses}"}), 400

    try:
        success = IncidentService.update_incident_status(clean_id, new_status, analyst=analyst, notes=notes)
        if not success:
            return jsonify({"error": f"Incident not found or could not be updated: {clean_id}"}), 404
        return jsonify({
            "message": "Incident status updated successfully",
            "incident_id": clean_id,
            "status": new_status,
            "analyst": analyst,
            "notes": notes
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to update status: {str(e)}"}), 500

