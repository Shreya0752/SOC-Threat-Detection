import requests
import json
import sys

BASE_URL = "http://127.0.0.1:5000"
session = requests.Session()

# Authenticate demo analyst
login_payload = {
    "username": "Shreya M",
    "password": "soc12345"
}
login_res = session.post(f"{BASE_URL}/api/login", json=login_payload)
if login_res.status_code != 200:
    print(f"FAILED to login: {login_res.status_code} {login_res.text}")
    sys.exit(1)
print(f"[AUTH] Logged in successfully: {login_res.json().get('user', {}).get('email')}")

results = {}

# 1. GET /api/v1/incidents
print("\n--- Testing GET /api/v1/incidents ---")
res = session.get(f"{BASE_URL}/api/v1/incidents?limit=5")
assert res.status_code == 200, f"Status: {res.status_code}"
inc_data = res.json()
assert "incidents" in inc_data and len(inc_data["incidents"]) > 0
first_inc = inc_data["incidents"][0]
print(f"Total incidents: {inc_data.get('total')}")
print(f"Sample incident keys: {list(first_inc.keys())}")
assert "affected_asset" in first_inc and first_inc["affected_asset"] == first_inc["asset_id"]
assert "risk_level" in first_inc and first_inc["risk_level"] == first_inc["priority"]
assert "reasons" in first_inc and first_inc["reasons"] == first_inc["explainability"]
assert "recommendations" in first_inc and first_inc["recommendations"] == first_inc["recommendation"]
assert "related_events" in first_inc
results["GET /api/v1/incidents"] = "PASS"

# 2. GET /api/v1/incidents/INC-998
print("\n--- Testing GET /api/v1/incidents/INC-998 ---")
res = session.get(f"{BASE_URL}/api/v1/incidents/INC-998")
assert res.status_code == 200, f"Status: {res.status_code}"
inc_998 = res.json()

required_fields = [
    "incident_id", "threat_type", "risk_score", "risk_level", "priority",
    "affected_asset", "asset_id", "ml_confidence", "related_events", "event_ids",
    "mitre_technique", "mitre_techniques", "reasons", "explainability",
    "recommendations", "recommendation", "status"
]

for field in required_fields:
    assert field in inc_998, f"Missing field: {field}"
    print(f"  [OK] {field}: {type(inc_998[field]).__name__} = {inc_998[field] if not isinstance(inc_998[field], list) else f'list len {len(inc_998[field])}'}")

# Verify equality of compatibility aliases
assert inc_998["affected_asset"] == inc_998["asset_id"]
assert inc_998["risk_level"] == inc_998["priority"]
assert inc_998["reasons"] == inc_998["explainability"]
assert inc_998["recommendations"] == inc_998["recommendation"]
assert "event_ids" in inc_998 and "detailed_events" in inc_998 and "related_events" in inc_998
results["GET /api/v1/incidents/INC-998"] = "PASS"

# 3. GET /api/v1/attack-chains
print("\n--- Testing GET /api/v1/attack-chains ---")
res = session.get(f"{BASE_URL}/api/v1/attack-chains")
assert res.status_code == 200, f"Status: {res.status_code}"
chain_data = res.json()
chains = chain_data.get("attack_chains", [])
print(f"Total attack chains: {len(chains)}")
assert len(chains) > 0
sample_chain = chains[0]

chain_fields = ["attack_chain_id", "incident_id", "events", "event_ids", "techniques", "stages", "risk_score", "confidence"]
for f in chain_fields:
    assert f in sample_chain, f"Missing chain field: {f}"
    print(f"  [OK] {f}: {type(sample_chain[f]).__name__} = {sample_chain[f] if not isinstance(sample_chain[f], list) else f'list len {len(sample_chain[f])}'}")

assert sample_chain["attack_chain_id"] == sample_chain["incident_id"]
results["GET /api/v1/attack-chains"] = "PASS"

# 4. GET /api/v1/risk/summary
print("\n--- Testing GET /api/v1/risk/summary ---")
res = session.get(f"{BASE_URL}/api/v1/risk/summary")
assert res.status_code == 200, f"Status: {res.status_code}"
summary = res.json()
print(f"Summary total incidents: {summary.get('total_incidents')}, open: {summary.get('open_incidents')}, critical: {summary.get('critical_count')}, database_status: {summary.get('database_status')}")
assert summary.get("total_incidents") == 1239
results["GET /api/v1/risk/summary"] = "PASS"

# 5. GET /api/v1/risk/high
print("\n--- Testing GET /api/v1/risk/high ---")
res = session.get(f"{BASE_URL}/api/v1/risk/high")
assert res.status_code == 200, f"Status: {res.status_code}"
high_data = res.json()
assert "high_risk_threats" in high_data and len(high_data["high_risk_threats"]) > 0
print(f"Total high/critical threats returned: {high_data.get('total_high_risk')}")
results["GET /api/v1/risk/high"] = "PASS"

# 6. POST /api/v1/risk/calculate
print("\n--- Testing POST /api/v1/risk/calculate ---")
calc_payload = {
    "threat_severity": "Critical",
    "ml_confidence": 95.0,
    "asset_name": "Database-01",
    "cvss_score": 9.8,
    "vulnerability_id": "CVE-2023-38606",
    "threat_match": True,
    "threat_severity_feed": "Critical",
    "threat_name": "Active Ransomware C2"
}
res = session.post(f"{BASE_URL}/api/v1/risk/calculate", json=calc_payload)
assert res.status_code == 200, f"Status: {res.status_code}"
calc_res = res.json()
print(f"Calculated risk_score: {calc_res.get('risk_score')}, priority: {calc_res.get('priority')}, risk_level: {calc_res.get('risk_level')}")
assert calc_res.get("risk_score") >= 81 and calc_res.get("risk_level") == "Critical"
assert "reasons" in calc_res and "explainability" in calc_res
results["POST /api/v1/risk/calculate"] = "PASS"

# 7. GET /api/v1/recommendations/INC-998
print("\n--- Testing GET /api/v1/recommendations/INC-998 ---")
res = session.get(f"{BASE_URL}/api/v1/recommendations/INC-998")
assert res.status_code == 200, f"Status: {res.status_code}"
rec_data = res.json()
print(f"Recommendations for INC-998: {len(rec_data.get('recommendations', []))} items")
assert "recommendations" in rec_data and "recommendation" in rec_data
assert "risk_score" in rec_data and "priority" in rec_data
results["GET /api/v1/recommendations/INC-998"] = "PASS"

print("\n" + "="*50)
print("ALL M3 API ENDPOINTS PASSED WITH SPECIFICATION ALIASES:")
for ep, st in results.items():
    print(f"  {ep}: {st}")
print("="*50)
