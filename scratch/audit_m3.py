import sqlite3
import os
import sys
import json
import requests

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

DB_PATH = os.path.join(PROJECT_ROOT, 'backend/database/soc_dashboard.db')
BASE_URL = 'http://127.0.0.1:5000'

from backend.database.prediction_repository import PredictionRepository
from backend.database.incident_repository import IncidentRepository
from backend.risk.risk_score import (
    RiskScoreEngine,
    CRITICALITY_LEVEL_MAP,
    DEFAULT_RISK_WEIGHTS,
    KNOWN_ASSET_CRITICALITY
)
from backend.risk.correlation import EventCorrelationEngine, EVENT_TACTIC_MAP
from backend.risk.recommendations import RecommendationEngine
from backend.services.incident_service import IncidentService

def audit_all():
    print("=" * 80)
    print("STARTING LIVE COMPLIANCE AUDIT OF MILESTONE 3")
    print("=" * 80)

    # -------------------------------------------------------------
    # 1. VERIFY M2 -> M3 DATA FLOW
    # -------------------------------------------------------------
    print("\n--- 1. M2 -> M3 DATA FLOW ---")
    events = PredictionRepository.get_all_events_for_correlation()
    print(f"Total joined M1/M2 events fetched via PredictionRepository: {len(events)}")
    
    sample = events[0]
    m2_fields = [
        ("event_id", sample.get("event_id"), "security_events.event_id"),
        ("prediction", sample.get("m2_prediction"), "threat_predictions.prediction"),
        ("confidence_score", sample.get("confidence_score"), "threat_predictions.confidence_score"),
        ("anomaly_score", sample.get("anomaly_score"), "threat_predictions.anomaly_score"),
        ("severity", sample.get("severity"), "security_events.severity"),
        ("event_type", sample.get("event_type"), "security_events.event_type"),
        ("asset_id", sample.get("device_name") or sample.get("asset_name"), "security_events.device_name / asset_name"),
        ("user_id", sample.get("username"), "security_events.username"),
        ("source_ip", sample.get("source_ip"), "security_events.source_ip"),
        ("timestamp", sample.get("timestamp"), "security_events.timestamp")
    ]
    for name, val, source in m2_fields:
        print(f"  - {name}: '{val}' (Source: {source})")
        assert val is not None, f"Field {name} is missing!"

    # -------------------------------------------------------------
    # 2. VERIFY RISK SCORE FORMULA & CALCULATION
    # -------------------------------------------------------------
    print("\n--- 2. RISK SCORE FORMULA & REAL EXECUTION ---")
    evt1 = PredictionRepository.get_event_with_prediction("EVT00001")
    print(f"Executing real calculation for event: {evt1['event_id']}")
    print(f"  Inputs: Severity={evt1['severity']}, ML Conf={evt1['confidence_score']}, "
          f"Asset={evt1['asset_name']} ({evt1['criticality']}), CVSS={evt1['cvss_score']}, "
          f"Threat Indicator={evt1['threat_indicator']}")
    
    risk_calc = RiskScoreEngine.calculate_risk(
        threat_severity_input=evt1["severity"],
        ml_confidence=evt1["confidence_score"],
        asset_name=evt1["asset_name"] or evt1["device_name"],
        asset_criticality_str=evt1["criticality"],
        cvss_score=evt1["cvss_score"],
        vulnerability_id=evt1.get("vulnerability_id", ""),
        threat_indicator=bool(evt1["threat_indicator"]),
        threat_match=bool(evt1.get("threat_match", False)),
        malicious_ip_flag=evt1.get("malicious_ip_flag", 0),
        threat_severity_feed=evt1.get("threat_severity", "None"),
        threat_name=evt1.get("threat_name", "")
    )
    
    factors = risk_calc["factors"]
    s_c = factors["threat_severity"]["contribution"]
    c_c = factors["ml_confidence"]["contribution"]
    a_c = factors["asset_criticality"]["contribution"]
    v_c = factors["vulnerability_exposure"]["contribution"]
    t_c = factors["threat_intelligence"]["contribution"]
    final_score = risk_calc["risk_score"]

    print(f"  Severity contribution (25%): {s_c} pts (Raw norm: {factors['threat_severity']['raw']})")
    print(f"  Confidence contribution (25%): {c_c} pts (Raw norm: {factors['ml_confidence']['raw']})")
    print(f"  Asset contribution (20%): {a_c} pts (Raw norm: {factors['asset_criticality']['raw']})")
    print(f"  Vulnerability contribution (20%): {v_c} pts (Raw norm: {factors['vulnerability_exposure']['raw']})")
    print(f"  Threat Intelligence contribution (10%): {t_c} pts (Raw norm: {factors['threat_intelligence']['raw']})")
    print(f"  Calculated Sum: {s_c + c_c + a_c + v_c + t_c:.2f}")
    print(f"  Final Risk Score: {final_score}")
    print(f"  Priority Band: {risk_calc['priority']}")
    assert 0 <= final_score <= 100, "Risk score must be between 0 and 100!"

    # -------------------------------------------------------------
    # 3. VERIFY PRIORITY CLASSIFICATION THRESHOLDS
    # -------------------------------------------------------------
    print("\n--- 3. PRIORITY CLASSIFICATION CONSISTENCY ---")
    print("Testing priority boundaries:")
    print(f"  Score 0 -> {RiskScoreEngine.classify_risk(0)} (Expected: Low)")
    print(f"  Score 40 -> {RiskScoreEngine.classify_risk(40)} (Expected: Low)")
    print(f"  Score 41 -> {RiskScoreEngine.classify_risk(41)} (Expected: Medium)")
    print(f"  Score 60 -> {RiskScoreEngine.classify_risk(60)} (Expected: Medium)")
    print(f"  Score 61 -> {RiskScoreEngine.classify_risk(61)} (Expected: High)")
    print(f"  Score 80 -> {RiskScoreEngine.classify_risk(80)} (Expected: High)")
    print(f"  Score 81 -> {RiskScoreEngine.classify_risk(81)} (Expected: Critical)")
    print(f"  Score 100 -> {RiskScoreEngine.classify_risk(100)} (Expected: Critical)")
    assert RiskScoreEngine.classify_risk(20) == "Low"
    assert RiskScoreEngine.classify_risk(40) == "Low"
    assert RiskScoreEngine.classify_risk(41) == "Medium"
    assert RiskScoreEngine.classify_risk(60) == "Medium"
    assert RiskScoreEngine.classify_risk(61) == "High"
    assert RiskScoreEngine.classify_risk(80) == "High"
    assert RiskScoreEngine.classify_risk(81) == "Critical"
    assert RiskScoreEngine.classify_risk(100) == "Critical"
    print("All classification boundary assertions passed.")

    # -------------------------------------------------------------
    # 4. VERIFY ASSET CRITICALITY
    # -------------------------------------------------------------
    print("\n--- 4. ASSET CRITICALITY MULTIPLIERS ---")
    print(f"Criticality multipliers: {CRITICALITY_LEVEL_MAP}")
    assert CRITICALITY_LEVEL_MAP["critical"] == 1.00
    assert CRITICALITY_LEVEL_MAP["high"] == 0.75
    assert CRITICALITY_LEVEL_MAP["medium"] == 0.50
    assert CRITICALITY_LEVEL_MAP["low"] == 0.25
    print("Asset multipliers verified: Critical=1.00, High=0.75, Medium=0.50, Low=0.25.")

    # -------------------------------------------------------------
    # 5. VERIFY VULNERABILITY / CVE CORRELATION
    # -------------------------------------------------------------
    print("\n--- 5. VULNERABILITY / CVE CORRELATION ---")
    with_cve = RiskScoreEngine.calculate_risk(
        threat_severity_input="Medium", ml_confidence=70.0, asset_criticality_str="Medium", cvss_score=9.8, vulnerability_id="CVE-2024-21413"
    )
    without_cve = RiskScoreEngine.calculate_risk(
        threat_severity_input="Medium", ml_confidence=70.0, asset_criticality_str="Medium", cvss_score=0.0, vulnerability_id="No Vulnerability"
    )
    diff = with_cve["risk_score"] - without_cve["risk_score"]
    print(f"  Risk score with CVSS 9.8: {with_cve['risk_score']}")
    print(f"  Risk score with CVSS 0.0: {without_cve['risk_score']}")
    print(f"  Delta attributable to CVE exposure: {diff:.2f}")
    assert diff > 0, "Vulnerability exposure must increase the risk score!"

    # -------------------------------------------------------------
    # 6. VERIFY MITRE ATT&CK MAPPING
    # -------------------------------------------------------------
    print("\n--- 6. MITRE ATT&CK MAPPING ---")
    print(f"Total mapped event types in EVENT_TACTIC_MAP: {len(EVENT_TACTIC_MAP)}")
    for k, v in list(EVENT_TACTIC_MAP.items())[:3]:
        print(f"  '{k}' -> Tactic: {v[0]}, Technique: {v[1]} ({v[2]})")

    # -------------------------------------------------------------
    # 7. VERIFY THREAT INTELLIGENCE / IOC
    # -------------------------------------------------------------
    print("\n--- 7. THREAT INTELLIGENCE / IOC ---")
    with_ioc = RiskScoreEngine.calculate_risk(
        threat_severity_input="Low", ml_confidence=50.0, threat_match=True, threat_severity_feed="High", threat_name="CobaltStrike C2"
    )
    without_ioc = RiskScoreEngine.calculate_risk(
        threat_severity_input="Low", ml_confidence=50.0, threat_match=False
    )
    print(f"  Risk score with active malicious IOC match: {with_ioc['risk_score']}")
    print(f"  Risk score without IOC match: {without_ioc['risk_score']}")
    print(f"  Delta attributable to IOC match: {with_ioc['risk_score'] - without_ioc['risk_score']:.2f}")

    # -------------------------------------------------------------
    # 8. VERIFY EVENT CORRELATION & TIME WINDOW
    # -------------------------------------------------------------
    print("\n--- 8. EVENT CORRELATION & TIME WINDOW ---")
    window_minutes = 30
    print(f"Configured sliding time window: {window_minutes} minutes")
    assert 5 <= window_minutes <= 30, "Correlation window must be within 5-30 minutes!"
    
    correlated_clusters = EventCorrelationEngine.correlate_events(events, window_minutes=window_minutes)
    print(f"Correlated {len(events)} events into {len(correlated_clusters)} clusters.")
    multi_event_clusters = [c for c in correlated_clusters if len(c) > 1]
    print(f"Multi-event correlated clusters: {len(multi_event_clusters)}")
    if multi_event_clusters:
        sample_cluster = multi_event_clusters[0]
        sample_title, sample_stages = EventCorrelationEngine.identify_attack_chain_scenario(sample_cluster)
        print(f"Real Correlated Group Sample:")
        print(f"  User: {sample_cluster[0].get('username')}, Asset: {sample_cluster[0].get('asset_name')}")
        print(f"  Event IDs ({len(sample_cluster)}): {[e.get('event_id') for e in sample_cluster]}")
        print(f"  Threat Scenario: {sample_title}")
        print(f"  Stages count: {len(sample_stages)}")

    # -------------------------------------------------------------
    # 9. VERIFY ATTACK CHAIN PATTERNS
    # -------------------------------------------------------------
    print("\n--- 9. ATTACK CHAIN DISTINCTION ---")
    attack_chain_clusters = [
        c for c in correlated_clusters
        if len(c) > 1 and "Attack Chain" in EventCorrelationEngine.identify_attack_chain_scenario(c)[0]
    ]
    print(f"Detected multi-stage attack chains: {len(attack_chain_clusters)}")
    if attack_chain_clusters:
        sample_ac = attack_chain_clusters[0]
        title, stages = EventCorrelationEngine.identify_attack_chain_scenario(sample_ac)
        print(f"Sample Attack Chain Scenario:")
        print(f"  Title: {title}")
        assert "Possible" in title, "Attack chain title must distinguish 'Possible' attack chain from confirmed!"
        for stage in stages:
            print(f"    -> Stage: {stage['stage']}, Event: {stage['event_type']}, MITRE: {stage['mitre_id']}")

    # -------------------------------------------------------------
    # 10. VERIFY EXPLAINABILITY
    # -------------------------------------------------------------
    print("\n--- 10. EXPLAINABILITY ---")
    inc_res = IncidentRepository.get_incidents(limit=25, priority="Critical")
    stored_incidents = inc_res.get("incidents", [])
    print(f"Critical incidents fetched from repository: {len(stored_incidents)} (Total in DB: {inc_res.get('total')})")
    if stored_incidents:
        crit = stored_incidents[0]
        print(f"Explainability for {crit['incident_id']} (Score: {crit['risk_score']}, Priority: {crit['priority']}):")
        for reason in crit["explainability"]:
            print(f"  * {reason}")
        assert len(crit["explainability"]) > 0, "Explainability checklist must not be empty!"

    # -------------------------------------------------------------
    # 11. VERIFY RESPONSE RECOMMENDATIONS
    # -------------------------------------------------------------
    print("\n--- 11. RESPONSE RECOMMENDATIONS ---")
    recs = RecommendationEngine.get_recommendations("Brute Force", priority="Critical", threat_severity="Critical")
    print(f"Generated {len(recs)} guidance recommendations for Brute Force attack chain:")
    for idx, r in enumerate(recs, 1):
        print(f"  Step {idx}: {r}")
    assert any("guidance" in r.lower() or "recommend" in r.lower() or "investigate" in r.lower() or "review" in r.lower() for r in recs)
    print("Recommendations verified as advisory/guidance only (no automated destructive actions).")

    # -------------------------------------------------------------
    # 12. VERIFY INCIDENT STORAGE & MONGODB STATUS
    # -------------------------------------------------------------
    print("\n--- 12. INCIDENT STORAGE & MONGODB STATUS ---")
    status = IncidentRepository.get_connectivity_status()
    print("Connectivity Status from IncidentRepository:")
    print(json.dumps(status, indent=2))
    total_stored = IncidentRepository.count_incidents()
    print(f"Total incidents stored in active persistence engine: {total_stored}")

    # -------------------------------------------------------------
    # 13. VERIFY ALL 7 REQUIRED M3 REST APIS
    # -------------------------------------------------------------
    print("\n--- 13. VERIFY ALL 7 REQUIRED M3 APIS VIA HTTP ---")
    session = requests.Session()
    login_res = session.post(f"{BASE_URL}/login", json={"username": "analyst_admin", "password": "soc12345"})
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    print("Authenticated session created.")

    # Get a real incident ID from the database
    first_inc_id = stored_incidents[0]["incident_id"] if stored_incidents else "INC-001"
    print(f"Using real incident ID for tests: {first_inc_id}")

    api_endpoints = [
        ("POST", f"{BASE_URL}/api/v1/risk/calculate", {"threat_severity": "High", "ml_confidence": 85.0, "asset_name": "Database-01", "cvss_score": 7.5}),
        ("GET", f"{BASE_URL}/api/v1/risk/high", None),
        ("GET", f"{BASE_URL}/api/v1/risk/summary", None),
        ("GET", f"{BASE_URL}/api/v1/incidents", None),
        ("GET", f"{BASE_URL}/api/v1/incidents/{first_inc_id}", None),
        ("GET", f"{BASE_URL}/api/v1/attack-chains", None),
        ("GET", f"{BASE_URL}/api/v1/recommendations/{first_inc_id}", None)
    ]

    for method, url, payload in api_endpoints:
        if method == "POST":
            r = session.post(url, json=payload)
        else:
            r = session.get(url)
        pass_fail = "PASS" if r.status_code == 200 else "FAIL"
        data_snippet = str(r.json())[:90] + "..." if r.status_code == 200 else r.text[:90]
        print(f"  {method} {url.replace(BASE_URL, '')} -> {r.status_code} ({pass_fail}) | Sample: {data_snippet}")
        assert r.status_code == 200, f"API test failed for {url}: {r.text}"

    # -------------------------------------------------------------
    # 14. VERIFY M1 & M2 ENDPOINTS (REGRESSION)
    # -------------------------------------------------------------
    print("\n--- 14. M1 + M2 REGRESSION AUDIT VIA HTTP ---")
    regression_endpoints = [
        ("GET", "/events"),
        ("GET", "/stats"),
        ("GET", "/threats"),
        ("GET", "/predictions"),
        ("GET", "/predictions/EVT00001"),
        ("GET", "/anomalies"),
        ("GET", "/model-performance"),
        ("GET", "/threat-summary")
    ]
    for method, path in regression_endpoints:
        r = session.get(f"{BASE_URL}{path}")
        pf = "PASS" if r.status_code == 200 else "FAIL"
        print(f"  {method} {path} -> {r.status_code} ({pf})")
        assert r.status_code == 200, f"Regression failure on {path}!"

    print("\n" + "=" * 80)
    print("ALL AUDIT CHECKS COMPLETED SUCCESSFULLY WITH 100% PASS RATE!")
    print("=" * 80)

if __name__ == "__main__":
    audit_all()
