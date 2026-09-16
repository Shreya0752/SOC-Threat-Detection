import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from backend.database.db import SessionLocal
from backend.models.database_models import SecurityEvent, ThreatPrediction
from backend.database.incident_repository import IncidentRepository

def test():
    db = SessionLocal()
    total_events = db.query(SecurityEvent).count()
    detected_threats = db.query(ThreatPrediction).filter(ThreatPrediction.prediction == "Anomalous").count()
    all_preds = db.query(ThreatPrediction).count()
    print(f"M1 Events: {total_events}")
    print(f"M2 Detected Anomalies: {detected_threats} / {all_preds} predictions")
    
    total_incidents = IncidentRepository.count_incidents()
    print(f"M3 Total Incidents: {total_incidents}")
    
    # Check priorities
    crit_incidents = IncidentRepository.get_incidents(priority="Critical", limit=0)
    high_incidents = IncidentRepository.get_incidents(priority="High", limit=0)
    print(f"Critical Incidents: {crit_incidents['total']}")
    print(f"High Incidents: {high_incidents['total']}")
    
    # Check statuses
    open_incidents = IncidentRepository.get_incidents(status="Open", limit=0)
    inv_incidents = IncidentRepository.get_incidents(status="Investigating", limit=0)
    res_incidents = IncidentRepository.get_incidents(status="Resolved", limit=0)
    fp_incidents = IncidentRepository.get_incidents(status="False Positive", limit=0)
    print(f"Status - Open: {open_incidents['total']}, Investigating: {inv_incidents['total']}, Resolved: {res_incidents['total']}, FP: {fp_incidents['total']}")
    
    # Check assets
    all_incs = IncidentRepository.get_incidents(limit=0)
    assets = set()
    for inc in all_incs["incidents"]:
        if inc.get("asset_id"):
            assets.add(inc.get("asset_id"))
    print(f"Unique Affected Assets ({len(assets)}): {sorted(list(assets))}")
    
    # Check sample incident timestamps
    sample_created = [i.get("created_at") for i in all_incs["incidents"][:5]]
    print("Sample incident created_at:", sample_created)
    
    db.close()

if __name__ == "__main__":
    test()
