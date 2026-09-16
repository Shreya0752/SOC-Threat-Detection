"""
Overview Routes Blueprint for Milestone 4 (backend/routes/overview_routes.py).
Exposes REST API endpoints for unified SOC command center:
- GET /api/v1/overview/summary
- GET /api/v1/overview/report
"""

import os
import sys
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, Response

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.routes.api import login_required
from backend.services.overview_service import OverviewService

overview_bp = Blueprint("overview_routes", __name__)


@overview_bp.route("/api/v1/overview/summary", methods=["GET"])
@login_required
def get_overview_summary():
    """
    GET /api/v1/overview/summary
    Retrieves dynamically computed M4 SOC overview telemetry:
    - 6 KPI counts
    - Security Posture score & status with transparent breakdown
    - Threat distributions (severity, type, status)
    - Multi-timeframe risk trends (24h, 7d, 30d)
    - Top critical incidents for immediate drill-down
    - Executive asset exposure metrics
    """
    try:
        summary = OverviewService.get_overview_summary()
        return jsonify(summary), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve overview summary: {str(e)}"}), 500


@overview_bp.route("/api/v1/overview/report", methods=["GET"])
@login_required
def download_security_report():
    """
    GET /api/v1/overview/report
    Generates and downloads a structured executive cybersecurity report in CSV format.
    """
    try:
        csv_data = OverviewService.generate_security_report_csv()
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"soc_security_report_{date_str}.csv"
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "text/csv; charset=utf-8"
            }
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate security report: {str(e)}"}), 500
