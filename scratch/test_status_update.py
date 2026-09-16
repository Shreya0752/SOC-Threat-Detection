import requests
import sys

BASE_URL = "http://127.0.0.1:5000"
session = requests.Session()

# Login
login_res = session.post(f"{BASE_URL}/api/login", json={"username": "Shreya M", "password": "soc12345"})
assert login_res.status_code == 200, f"Login failed: {login_res.text}"
print("[AUTH] Successfully logged in.")

# Get a test incident, e.g. INC-998
incident_id = "INC-998"
inc_before = session.get(f"{BASE_URL}/api/v1/incidents/{incident_id}").json()
print(f"Incident {incident_id} initial status: {inc_before.get('status')}")
initial_status = inc_before.get("status")

# Record baseline intelligence metrics
baseline_score = inc_before.get("risk_score")
baseline_priority = inc_before.get("priority")
baseline_risk_level = inc_before.get("risk_level")
baseline_ml_conf = inc_before.get("ml_confidence")
baseline_asset = inc_before.get("asset_id")
baseline_threat = inc_before.get("threat_type")
baseline_reasons = inc_before.get("reasons")
baseline_recs = inc_before.get("recommendations")

# 1. Update status to 'Investigating'
target_status = "Investigating" if initial_status != "Investigating" else "Open"
print(f"Updating {incident_id} status to: {target_status}")
patch_res = session.patch(f"{BASE_URL}/api/v1/incidents/{incident_id}/status", json={"status": target_status})
assert patch_res.status_code == 200, f"PATCH failed: {patch_res.status_code} {patch_res.text}"
print(f"PATCH response: {patch_res.json()}")

# 2. Re-fetch incident from API (persistence check)
inc_after = session.get(f"{BASE_URL}/api/v1/incidents/{incident_id}").json()
print(f"Re-fetched status: {inc_after.get('status')}")
assert inc_after.get("status") == target_status, f"Expected {target_status}, got {inc_after.get('status')}"

# 3. Verify ALL risk intelligence fields remain 100% UNCHANGED
assert inc_after.get("risk_score") == baseline_score, "risk_score was modified!"
assert inc_after.get("priority") == baseline_priority, "priority was modified!"
assert inc_after.get("risk_level") == baseline_risk_level, "risk_level was modified!"
assert inc_after.get("ml_confidence") == baseline_ml_conf, "ml_confidence was modified!"
assert inc_after.get("asset_id") == baseline_asset, "asset_id was modified!"
assert inc_after.get("threat_type") == baseline_threat, "threat_type was modified!"
assert inc_after.get("reasons") == baseline_reasons, "reasons was modified!"
assert inc_after.get("recommendations") == baseline_recs, "recommendations was modified!"
print("[VERIFY] All risk score and security intelligence fields remained strictly UNCHANGED.")

# 4. Restore original status to preserve clean database state
restore_res = session.patch(f"{BASE_URL}/api/v1/incidents/{incident_id}/status", json={"status": initial_status})
assert restore_res.status_code == 200
inc_restored = session.get(f"{BASE_URL}/api/v1/incidents/{incident_id}").json()
assert inc_restored.get("status") == initial_status
print(f"[RESTORE] Incident {incident_id} status restored to: {initial_status}")

print("="*50)
print("STATUS UPDATE AND PERSISTENCE VERIFICATION: 100% PASS")
print("="*50)
