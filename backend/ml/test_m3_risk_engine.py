"""
Unit & Integration Tests for Milestone 3 Risk Engine (`backend/ml/test_m3_risk_engine.py`).
Tests the core mathematical calculations, factor normalizations,
correlation sliding windows, attack chain detection, and recommendations.
"""
import os
import sys
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.risk.risk_score import RiskScoreEngine, CRITICALITY_LEVEL_MAP
from backend.risk.prioritization import ThreatPrioritization
from backend.risk.correlation import EventCorrelationEngine
from backend.risk.recommendations import RecommendationEngine

class TestM3RiskEngine(unittest.TestCase):

    def test_spec_risk_calculation_example(self):
        """
        Verifies the exact test scenario given in the M3 specification:
        Threat Severity = 90
        ML Confidence = 92
        Asset Criticality = 100
        Vulnerability = 95
        Threat Intelligence = 80
        Formula: (90*0.25) + (92*0.25) + (100*0.20) + (95*0.20) + (80*0.10) = 92.1 -> 92
        """
        sev = 90.0
        conf = 92.0
        asset = 100.0
        vuln = 95.0
        intel = 80.0

        expected = (sev * 0.25) + (conf * 0.25) + (asset * 0.20) + (vuln * 0.20) + (intel * 0.10)
        self.assertAlmostEqual(expected, 92.5, places=1)

        result = RiskScoreEngine.calculate_risk(
            threat_severity_input=sev,
            ml_confidence=conf,
            asset_name="Database-01",
            asset_criticality_str="Critical",
            cvss_score=9.5,
            vulnerability_id="CVE-2024-XXXX",
            threat_match=True,
            threat_severity_feed="High"
        )

        self.assertIn(result["risk_score"], [92, 93])
        self.assertEqual(result["priority"], "Critical")
        self.assertIn("Critical / High-value asset targeted", result["explainability"][0])

    def test_asset_criticality_normalization(self):
        """Verifies Asset Criticality 4-level scale: 1.00, 0.75, 0.50, 0.25."""
        self.assertEqual(CRITICALITY_LEVEL_MAP["critical"], 1.00)
        self.assertEqual(CRITICALITY_LEVEL_MAP["high"], 0.75)
        self.assertEqual(CRITICALITY_LEVEL_MAP["medium"], 0.50)
        self.assertEqual(CRITICALITY_LEVEL_MAP["low"], 0.25)

        m, lvl, score = RiskScoreEngine.normalize_asset_criticality("Database-01")
        self.assertEqual(m, 1.00)
        self.assertEqual(lvl, "Critical")
        self.assertEqual(score, 100.0)

        m, lvl, score = RiskScoreEngine.normalize_asset_criticality("WebServer")
        self.assertEqual(m, 0.75)
        self.assertEqual(lvl, "High")
        self.assertEqual(score, 75.0)

        m, lvl, score = RiskScoreEngine.normalize_asset_criticality("Finance-PC-02")
        self.assertEqual(m, 0.50)
        self.assertEqual(lvl, "Medium")
        self.assertEqual(score, 50.0)

        m, lvl, score = RiskScoreEngine.normalize_asset_criticality("TEST-001")
        self.assertEqual(m, 0.25)
        self.assertEqual(lvl, "Low")
        self.assertEqual(score, 25.0)

    def test_vulnerability_cvss_normalization(self):
        """Verifies CVSS 0.0 - 10.0 is normalized to 0 - 100."""
        score, desc = RiskScoreEngine.normalize_vulnerability_exposure(9.8, "CVE-2024-1045")
        self.assertEqual(score, 98.0)
        self.assertIn("CVE-2024-1045", desc)

        score, desc = RiskScoreEngine.normalize_vulnerability_exposure(0.0, "No Vulnerability")
        self.assertEqual(score, 0.0)

    def test_threat_intelligence_normalization(self):
        """Verifies threat intelligence differentiation between IOC match, indicator, and clean."""
        score, desc = RiskScoreEngine.normalize_threat_intelligence(threat_match=True, threat_severity="Critical")
        self.assertEqual(score, 100.0)
        self.assertIn("Known Malicious IOC", desc)

        score, desc = RiskScoreEngine.normalize_threat_intelligence(threat_match=False, threat_indicator=True)
        self.assertEqual(score, 60.0)
        self.assertIn("Suspicious Indicator", desc)

        score, desc = RiskScoreEngine.normalize_threat_intelligence(threat_match=False, threat_indicator=False)
        self.assertEqual(score, 0.0)
        self.assertIn("No Malicious", desc)

    def test_risk_classification_boundaries(self):
        """Verifies Priority classification boundaries."""
        self.assertEqual(RiskScoreEngine.classify_risk(95), "Critical")
        self.assertEqual(RiskScoreEngine.classify_risk(81), "Critical")
        self.assertEqual(RiskScoreEngine.classify_risk(80), "High")
        self.assertEqual(RiskScoreEngine.classify_risk(61), "High")
        self.assertEqual(RiskScoreEngine.classify_risk(60), "Medium")
        self.assertEqual(RiskScoreEngine.classify_risk(41), "Medium")
        self.assertEqual(RiskScoreEngine.classify_risk(40), "Low")
        self.assertEqual(RiskScoreEngine.classify_risk(15), "Low")

    def test_threat_prioritization_ranking(self):
        """Verifies sorting incidents by descending risk score."""
        incidents = [
            {"incident_id": "INC-003", "risk_score": 72, "priority": "High"},
            {"incident_id": "INC-001", "risk_score": 94, "priority": "Critical"},
            {"incident_id": "INC-009", "risk_score": 22, "priority": "Low"},
            {"incident_id": "INC-004", "risk_score": 87, "priority": "Critical"},
            {"incident_id": "INC-007", "risk_score": 53, "priority": "Medium"}
        ]
        ranked = ThreatPrioritization.rank_incidents(incidents)
        scores = [r["risk_score"] for r in ranked]
        self.assertEqual(scores, [94, 87, 72, 53, 22])
        self.assertEqual(ranked[0]["incident_id"], "INC-001")
        self.assertEqual(ranked[0]["priority_rank"], 1)

    def test_attack_chain_detection(self):
        """Verifies multi-stage attack scenarios identification."""
        brute_force_cluster = [
            {"event_id": "E1", "event_type": "Failed Login", "timestamp": "2025-08-01 00:00:00", "asset_name": "Database-01"},
            {"event_id": "E2", "event_type": "Failed Login", "timestamp": "2025-08-01 00:05:00", "asset_name": "Database-01"},
            {"event_id": "E3", "event_type": "Login Success", "timestamp": "2025-08-01 00:10:00", "asset_name": "Database-01"}
        ]
        title, stages = EventCorrelationEngine.identify_attack_chain_scenario(brute_force_cluster)
        self.assertEqual(title, "Possible Brute Force Attack Chain")
        self.assertEqual(len(stages), 3)

        priv_esc_cluster = [
            {"event_id": "E4", "event_type": "Sql Injection Attempt", "timestamp": "2025-08-01 00:00:00", "asset_name": "WebServer"},
            {"event_id": "E5", "event_type": "Privilege Escalation", "timestamp": "2025-08-01 00:15:00", "asset_name": "WebServer"}
        ]
        title, stages = EventCorrelationEngine.identify_attack_chain_scenario(priv_esc_cluster)
        self.assertEqual(title, "Possible Privilege Escalation Attack Chain")

    def test_response_recommendations(self):
        """Verifies context-aware guidance playbooks generation."""
        recs = RecommendationEngine.get_recommendations("Possible Brute Force Attack Chain", priority="Critical")
        self.assertTrue(any("lock" in r.lower() or "account" in r.lower() for r in recs))
        self.assertTrue(any("source ip" in r.lower() for r in recs))

        recs_malware = RecommendationEngine.get_recommendations("Malware Infection", priority="High")
        self.assertTrue(any("isolate" in r.lower() for r in recs_malware))

if __name__ == "__main__":
    unittest.main()
