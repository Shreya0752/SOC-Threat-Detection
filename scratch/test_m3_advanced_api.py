"""
Test Suite for Advanced Milestone 3 Endpoints & Features
(`scratch/test_m3_advanced_api.py`)
"""
import os
import sys
import json
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.app import app
from backend.database.incident_repository import IncidentRepository
from backend.risk.risk_score import RiskScoreEngine

class TestM3AdvancedFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        IncidentRepository.initialize()
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def setUp(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "analyst_admin"
            sess["role"] = "Tier 2 Security Analyst"

    def test_01_weights_endpoints(self):
        # GET weights
        res = self.client.get('/api/v1/risk/weights')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("weights", data)
        self.assertIn("threat_severity", data["weights"])
        self.assertIn("formula", data)

        # PUT weights with valid sum
        new_weights = {
            "threat_severity": 0.30,
            "ml_confidence": 0.20,
            "asset_criticality": 0.25,
            "vulnerability_exposure": 0.15,
            "threat_intelligence": 0.10
        }
        res_put = self.client.put('/api/v1/risk/weights', json={"weights": new_weights})
        self.assertEqual(res_put.status_code, 200)
        self.assertEqual(res_put.get_json()["weights"]["threat_severity"], 0.30)

        # PUT invalid weights
        bad_weights = {
            "threat_severity": 0.50,
            "ml_confidence": 0.50,
            "asset_criticality": 0.50,
            "vulnerability_exposure": 0.50,
            "threat_intelligence": 0.50
        }
        res_bad = self.client.put('/api/v1/risk/weights', json={"weights": bad_weights})
        self.assertEqual(res_bad.status_code, 400)

        # Reset weights
        res_reset = self.client.post('/api/v1/risk/weights/reset')
        self.assertEqual(res_reset.status_code, 200)
        self.assertEqual(res_reset.get_json()["weights"]["threat_severity"], 0.25)

    def test_02_incident_risk_comparison(self):
        # Fetch an incident id first
        inc_res = self.client.get('/api/v1/incidents?limit=1')
        self.assertEqual(inc_res.status_code, 200)
        inc_list = inc_res.get_json().get("incidents", [])
        self.assertGreater(len(inc_list), 0)
        inc_id = inc_list[0]["incident_id"]

        comp_res = self.client.get(f'/api/v1/incidents/{inc_id}/risk-comparison')
        self.assertEqual(comp_res.status_code, 200)
        comp_data = comp_res.get_json()
        self.assertIn("isolated_score", comp_data)
        self.assertIn("correlated_score", comp_data)
        self.assertIn("delta", comp_data)
        self.assertIn("reasons", comp_data)
        self.assertIsInstance(comp_data["reasons"], list)

    def test_03_incident_timeline(self):
        inc_res = self.client.get('/api/v1/incidents?limit=1')
        inc_id = inc_res.get_json()["incidents"][0]["incident_id"]

        time_res = self.client.get(f'/api/v1/incidents/{inc_id}/timeline')
        self.assertEqual(time_res.status_code, 200)
        time_data = time_res.get_json()
        self.assertIn("timeline", time_data)
        self.assertGreater(len(time_data["timeline"]), 0)

    def test_04_analyst_feedback(self):
        inc_res = self.client.get('/api/v1/incidents?limit=1')
        inc_id = inc_res.get_json()["incidents"][0]["incident_id"]

        fb_res = self.client.post(f'/api/v1/incidents/{inc_id}/feedback', json={
            "feedback": "True Positive",
            "notes": "Verified malicious beaconing on domain controller",
            "analyst": "Senior SOC Analyst Alex"
        })
        self.assertEqual(fb_res.status_code, 200)

        # Check incident details show feedback
        check_res = self.client.get(f'/api/v1/incidents/{inc_id}')
        inc_data = check_res.get_json()
        self.assertEqual(inc_data.get("analyst_feedback"), "True Positive")
        self.assertEqual(inc_data.get("feedback_analyst"), "Senior SOC Analyst Alex")

    def test_05_status_update_with_audit_history(self):
        inc_res = self.client.get('/api/v1/incidents?limit=1')
        inc_id = inc_res.get_json()["incidents"][0]["incident_id"]

        status_res = self.client.patch(f'/api/v1/incidents/{inc_id}/status', json={
            "status": "Investigating",
            "analyst": "Analyst Sarah",
            "notes": "Quarantined endpoint for forensic analysis"
        })
        self.assertEqual(status_res.status_code, 200)

        check_res = self.client.get(f'/api/v1/incidents/{inc_id}')
        inc_data = check_res.get_json()
        self.assertEqual(inc_data.get("status"), "Investigating")
        self.assertGreater(len(inc_data.get("status_history", [])), 0)

    def test_06_intelligence_overview(self):
        res = self.client.get('/api/v1/intelligence/overview')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("threat_intelligence", data)
        self.assertIn("vulnerability_intelligence", data)
        self.assertIn("mitre_intelligence", data)
        self.assertIn("asset_intelligence", data)
        self.assertGreater(data["threat_intelligence"]["total_threat_indicators"], 0)
        self.assertGreater(data["vulnerability_intelligence"]["total_cves_tracked"], 0)
        self.assertGreater(data["mitre_intelligence"]["total_tactics_observed"], 0)
        self.assertGreater(data["asset_intelligence"]["total_managed_assets"], 0)

    def test_07_advanced_sorting_and_filtering(self):
        # Sort by asset_id
        res = self.client.get('/api/v1/incidents?sort_by=asset_id&sort_order=asc&limit=10')
        self.assertEqual(res.status_code, 200)
        incidents = res.get_json()["incidents"]
        self.assertGreater(len(incidents), 0)

        # Filter by department
        res_dept = self.client.get('/api/v1/incidents?department=IT&limit=5')
        self.assertEqual(res_dept.status_code, 200)

if __name__ == "__main__":
    unittest.main()
