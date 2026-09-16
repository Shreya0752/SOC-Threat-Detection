"""
Intelligence Routes Blueprint for Milestone 3 (`backend/routes/intelligence_routes.py`).
Exposes M3 REST API endpoints for MITRE ATT&CK taxonomy context and asset criticality configurations.
"""
import os
import sys
from flask import Blueprint, jsonify

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.routes.api import login_required
from backend.services.intelligence_service import IntelligenceService

intel_bp = Blueprint("intelligence_routes", __name__)

@intel_bp.route("/api/v1/intelligence/mitre", methods=["GET"])
@login_required
def get_mitre_taxonomy():
    """
    GET /api/v1/intelligence/mitre
    Retrieves MITRE ATT&CK kill-chain tactics and technique mappings.
    """
    try:
        data = IntelligenceService.get_mitre_taxonomy()
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve MITRE context: {str(e)}"}), 500

@intel_bp.route("/api/v1/intelligence/assets", methods=["GET"])
@login_required
def get_asset_criticality():
    """
    GET /api/v1/intelligence/assets
    Retrieves asset criticality matrix and normalized weights.
    """
    try:
        data = IntelligenceService.get_asset_criticality_table()
        return jsonify({"assets": data}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve asset criticality matrix: {str(e)}"}), 500

@intel_bp.route("/api/v1/intelligence/overview", methods=["GET"])
@login_required
def get_intelligence_overview():
    """
    GET /api/v1/intelligence/overview
    Retrieves unified 4-quadrant security intelligence (Threat, Vuln, MITRE, Asset)
    aggregated directly from genuine database records.
    """
    try:
        data = IntelligenceService.get_intelligence_overview()
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve security intelligence overview: {str(e)}"}), 500

