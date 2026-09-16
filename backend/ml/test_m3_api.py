"""
Acceptance Test Suite for Milestone 3 APIs (`backend/ml/test_m3_api.py`).
Verifies all M3 REST API endpoints, status codes, payload structures,
and authentication via Flask test client.
"""
import os
import sys
import unittest
import json

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.app import app
from backend.services.incident_service import IncidentService

class TestM3APIs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test-secret-key"
        cls.client = app.test_client()

        # Bootstrap M3 incidents for testing
        IncidentService.bootstrap_incidents_from_data(force_reseed=True)

    def login_client(self):
        """Helper to establish authenticated session with demo user."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "analyst_admin"
            sess["role"] = "Tier 2 Security Analyst"

    def test_unauthorized_access(self):
        """Verifies 401 Unauthorized when not logged in."""
        unauth_client = app.test_client()
        res = unauth_client.get("/api/v1/incidents")
        self.assertEqual(res.status_code, 401)

        res = unauth_client.get("/api/v1/risk/summary")
        self.assertEqual(res.status_code, 401)

        res = unauth_client.post("/api/v1/risk/calculate", json={})
        self.assertEqual(res.status_code, 401)

    def test_post_risk_calculate(self):
        """POST /api/v1/risk/calculate with real event payload."""
        self.login_client()
        payload = {
            "threat_severity": "Critical",
            "confidence_score": 91.0,
            "asset_name": "Database-01",
            "criticality": "Critical",
            "cvss_score": 9.8,
            "vulnerability_id": "CVE-2024-1045",
            "threat_match": True,
            "threat_severity_feed": "High"
        }
        res = self.client.post("/api/v1/risk/calculate", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("risk_score", data)
        self.assertIn("priority", data)
        self.assertEqual(data["priority"], "Critical")
        self.assertGreaterEqual(data["risk_score"], 85)
        self.assertIn("factors", data)
        self.assertIn("explainability", data)

    def test_get_risk_high(self):
        """GET /api/v1/risk/high retrieves high priority threats."""
        self.login_client()
        res = self.client.get("/api/v1/risk/high?limit=10")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("high_risk_threats", data)
        self.assertIsInstance(data["high_risk_threats"], list)

    def test_get_risk_summary(self):
        """GET /api/v1/risk/summary retrieves summary telemetry."""
        self.login_client()
        res = self.client.get("/api/v1/risk/summary")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("total_incidents", data)
        self.assertIn("critical_count", data)
        self.assertIn("high_count", data)
        self.assertIn("average_risk_score", data)
        self.assertIn("database_status", data)

    def test_get_incidents_and_prioritization(self):
        """GET /api/v1/incidents returns incidents sorted by risk descending."""
        self.login_client()
        res = self.client.get("/api/v1/incidents?limit=25")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("incidents", data)
        self.assertGreater(len(data["incidents"]), 0)

        # Check descending order of risk_score
        scores = [inc["risk_score"] for inc in data["incidents"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

        first_inc = data["incidents"][0]
        self.assertIn("incident_id", first_inc)
        self.assertIn("threat_type", first_inc)
        self.assertIn("priority", first_inc)
        self.assertIn("priority_rank", first_inc)

    def test_get_incident_details(self):
        """GET /api/v1/incidents/<incident_id> retrieves full incident with events."""
        self.login_client()
        # Fetch first incident ID
        list_res = self.client.get("/api/v1/incidents?limit=1")
        first_id = list_res.get_json()["incidents"][0]["incident_id"]

        res = self.client.get(f"/api/v1/incidents/{first_id}")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["incident_id"], first_id)
        self.assertIn("recommendation", data)
        self.assertIn("detailed_events", data)
        self.assertIn("risk_factors", data)
        self.assertIn("explainability", data)

    def test_get_attack_chains(self):
        """GET /api/v1/attack-chains returns multi-stage attack scenarios."""
        self.login_client()
        res = self.client.get("/api/v1/attack-chains")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("attack_chains", data)
        self.assertIsInstance(data["attack_chains"], list)

    def test_get_recommendations(self):
        """GET /api/v1/recommendations/<incident_id> returns playbooks."""
        self.login_client()
        list_res = self.client.get("/api/v1/incidents?limit=1")
        first_id = list_res.get_json()["incidents"][0]["incident_id"]

        res = self.client.get(f"/api/v1/recommendations/{first_id}")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("recommendations", data)
        self.assertGreater(len(data["recommendations"]), 0)

    def test_update_incident_status(self):
        """PATCH /api/v1/incidents/<incident_id>/status updates status."""
        self.login_client()
        list_res = self.client.get("/api/v1/incidents?limit=1")
        first_id = list_res.get_json()["incidents"][0]["incident_id"]

        patch_res = self.client.patch(f"/api/v1/incidents/{first_id}/status", json={"status": "Investigating"})
        self.assertEqual(patch_res.status_code, 200)

        get_res = self.client.get(f"/api/v1/incidents/{first_id}")
        self.assertEqual(get_res.get_json()["status"], "Investigating")

if __name__ == "__main__":
    unittest.main()
