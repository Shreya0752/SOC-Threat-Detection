"""
Unit and Integration Test for M4 Overview Endpoints (scratch/test_m4_overview_api.py).
Tests:
1. OverviewService.get_overview_summary() logic, 6 KPIs, Posture formula, Distributions, Trends.
2. OverviewService.generate_security_report_csv() formatting.
3. Flask endpoints GET /api/v1/overview/summary and GET /api/v1/overview/report with authenticated session.
"""

import os
import sys
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.app import app
from backend.services.overview_service import OverviewService


class TestM4OverviewAPI(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    def test_01_service_overview_summary(self):
        summary = OverviewService.get_overview_summary()
        self.assertTrue(summary["success"])
        
        # Verify 6 KPIs
        kpis = summary["kpis"]
        self.assertEqual(kpis["total_security_events"], 1800)
        self.assertEqual(kpis["detected_threats"], 1207)
        self.assertGreater(kpis["critical_threats"], 0)
        self.assertGreater(kpis["high_risk_incidents"], 0)
        self.assertGreater(kpis["active_incidents"], 0)
        self.assertEqual(kpis["affected_assets"], 5)
        self.assertIn("Database-01", kpis["affected_assets_list"])
        self.assertIn("WebServer", kpis["affected_assets_list"])

        # Verify Security Posture
        posture = summary["security_posture"]
        self.assertGreaterEqual(posture["score"], 0)
        self.assertLessEqual(posture["score"], 100)
        self.assertIn(posture["status"], ["Good", "Moderate", "Needs Attention", "Critical"])
        self.assertIn("breakdown", posture)
        self.assertIn("penalties", posture["breakdown"])
        self.assertIn("credits", posture["breakdown"])

        # Verify Distributions
        dists = summary["threat_distribution"]
        self.assertIn("Critical", dists["severity"])
        self.assertIn("High", dists["severity"])
        self.assertGreater(len(dists["threat_types"]), 0)
        self.assertIn("Open", dists["status"])

        # Verify Risk Trends
        trends = summary["risk_trends"]
        self.assertIn("24h", trends["timeframes"])
        self.assertIn("7d", trends["timeframes"])
        self.assertIn("30d", trends["timeframes"])
        self.assertGreater(len(trends["timeframes"]["7d"]), 0)

        # Verify Critical Incidents Panel
        crit_panel = summary["critical_incidents"]
        self.assertGreater(len(crit_panel), 0)
        for item in crit_panel:
            self.assertEqual(item["priority"], "Critical")
            self.assertEqual(item["risk_level"], "Critical")
            self.assertIn("affected_asset", item)
            self.assertIn("reasons", item)
            self.assertIn("recommendations", item)

    def test_02_service_security_report_csv(self):
        csv_str = OverviewService.generate_security_report_csv()
        self.assertIn("SOC THREATDETECT AI - EXECUTIVE SECURITY AUDIT REPORT", csv_str)
        self.assertIn("Security Posture Score", csv_str)
        self.assertIn("Total Security Events (M1)", csv_str)
        self.assertIn("TOP CRITICAL INCIDENTS", csv_str)
        self.assertIn("OPERATIONAL ADVISORY NOTICE", csv_str)

    def test_03_authenticated_api_overview_endpoints(self):
        # 1. Login
        login_res = self.app.post("/login", json={
            "username": "analyst_admin",
            "password": "soc12345"
        })
        self.assertEqual(login_res.status_code, 200)

        # 2. GET /api/v1/overview/summary
        sum_res = self.app.get("/api/v1/overview/summary")
        self.assertEqual(sum_res.status_code, 200)
        sum_json = sum_res.get_json()
        self.assertTrue(sum_json.get("success"))
        self.assertEqual(sum_json["kpis"]["total_security_events"], 1800)

        # 3. GET /api/v1/overview/report
        rep_res = self.app.get("/api/v1/overview/report")
        self.assertEqual(rep_res.status_code, 200)
        self.assertEqual(rep_res.headers.get("Content-Type"), "text/csv; charset=utf-8")
        self.assertIn("attachment; filename=soc_security_report_", rep_res.headers.get("Content-Disposition", ""))
        self.assertIn("SOC THREATDETECT AI", rep_res.data.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
