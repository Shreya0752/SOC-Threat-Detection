import os
import sys
import json
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, PROJECT_ROOT)

# Load environment variables from .env
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

from backend.models.database_models import Base, SecurityEvent, CleaningStats, User, ThreatPrediction
from backend.preprocessing.pipeline import run_pipeline

DB_PATH = os.path.join(os.path.dirname(__file__), "soc_dashboard.db")
DATABASE_URI = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URI, echo=False, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """Provides a database session generator."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def seed_demo_user(db):
    """Seeds or updates the default demo SOC Analyst account with a hashed password."""
    username = os.getenv("SOC_ADMIN_USERNAME", "analyst_admin")
    raw_password = os.getenv("SOC_ADMIN_PASSWORD", "soc12345")
    hashed_password = generate_password_hash(raw_password)

    user = db.query(User).filter(User.username == username).first()
    if not user:
        user = User(
            username=username,
            password_hash=hashed_password,
            role="Tier 2 Security Analyst"
        )
        db.add(user)
    else:
        user.password_hash = hashed_password
        user.role = "Tier 2 Security Analyst"
    db.commit()
    print(f"[Database] Demo user '{username}' seeded successfully with secure password hash.")

def init_db(force_reseed=False):
    """
    Initializes SQLite tables and seeds the database using the preprocessing pipeline and demo user.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    Base.metadata.create_all(bind=engine)

    # Ensure threat_predictions table schema contains explanation column
    with engine.connect() as conn:
        cursor = conn.exec_driver_sql("PRAGMA table_info(threat_predictions)")
        cols = [row[1] for row in cursor.fetchall()]
        if cols and "explanation" not in cols:
            conn.exec_driver_sql("ALTER TABLE threat_predictions ADD COLUMN explanation VARCHAR(1000) DEFAULT '[]'")
            conn.commit()

    db = SessionLocal()
    
    try:
        # Always ensure demo user exists
        seed_demo_user(db)

        existing_count = db.query(SecurityEvent).count()
        if existing_count > 0 and not force_reseed:
            print(f"[Database] Found {existing_count} existing security events in database.")
            return

        print("[Database] Seeding database from preprocessing pipeline...")
        # Run preprocessing pipeline
        summary_stats, enriched_df = run_pipeline(data_dir="backend/data", output_dir="output")

        # Clear old event records if force reseed
        db.query(SecurityEvent).delete()
        db.query(CleaningStats).delete()
        db.commit()

        # Seed CleaningStats
        stats_record = CleaningStats(
            rows_before_cleaning=summary_stats.get("rows_before_cleaning", 0),
            rows_after_cleaning=summary_stats.get("rows_after_cleaning", 0),
            duplicates_removed=summary_stats.get("duplicates_removed", 0),
            missing_values_handled=summary_stats.get("missing_values_handled", 0),
            invalid_timestamps_handled=summary_stats.get("invalid_timestamps_handled", 0),
            threat_matches=summary_stats.get("threat_matches", 0),
            total_events=summary_stats.get("total_events", 0),
            mitre_mapped_events=summary_stats.get("mitre_mapped_events", 0),
            mitre_unmapped_events=summary_stats.get("mitre_unmapped_events", 0),
            mitre_mapping_percentage=summary_stats.get("mitre_mapping_percentage", 0.0)
        )
        db.add(stats_record)

        # Seed SecurityEvents in bulk
        events_to_insert = []
        for idx, row in enriched_df.iterrows():
            evt = SecurityEvent(
                event_id=str(row["event_id"]),
                timestamp=str(row["timestamp"]),
                source_ip=str(row.get("source_ip", "")),
                destination_ip=str(row.get("destination_ip", "")),
                username=str(row.get("username", "")),
                event_type=str(row.get("event_type", "")),
                protocol=str(row.get("protocol", "")),
                source_country=str(row.get("source_country", "")),
                destination_country=str(row.get("destination_country", "")),
                device_name=str(row.get("device_name", "")),
                os=str(row.get("os", "")),
                status=str(row.get("status", "Success")),
                severity=str(row.get("severity", "Low")),
                risk_label=str(row.get("risk_label", "Low Risk")),
                failed_login_attempts=int(row.get("failed_login_attempts", 0)),
                malware_detected=str(row.get("malware_detected", "No")),
                vulnerability_id=str(row.get("vulnerability_id", "No Vulnerability")),
                cvss_score=float(row.get("cvss_score", 0.0)),
                asset_name=str(row.get("asset_name", "Unknown Asset")),
                department=str(row.get("department", "General")),

                # Threat fields
                threat_indicator=bool(row.get("threat_indicator", False)),
                threat_match=bool(row.get("threat_match", False)),
                threat_name=str(row.get("threat_name", "No Match")),
                threat_actor=str(row.get("threat_actor", "Unknown")),
                confidence=str(row.get("confidence", "Unknown")),
                threat_severity=str(row.get("threat_severity", "None")),
                indicator_type=str(row.get("indicator_type", "IP Address")),

                # MITRE fields
                mitre_id=str(row.get("mitre_id", "Unknown")),
                technique_name=str(row.get("technique_name", "Unknown")),
                tactic=str(row.get("tactic", "Unknown")),
                mitre_mapped=int(row.get("mitre_mapped", 0)),

                # Asset lookups
                asset_type=str(row.get("asset_type", "Unknown")),
                owner=str(row.get("owner", "Unknown")),
                criticality=str(row.get("criticality", "Unknown")),
                vulnerability_name=str(row.get("vulnerability_name", "No Vulnerability")),
                patch_available=str(row.get("patch_available", "Unknown")),

                # Incident lookups
                incident_id=str(row.get("incident_id", "None")),
                incident_type=str(row.get("incident_type", "No Incident")),
                assigned_to=str(row.get("assigned_to", "Unassigned")),
                incident_status=str(row.get("status_incident", "Open")),

                # Features
                failed_login_count=int(row.get("failed_login_count", 0)),
                hour_of_day=int(row.get("hour_of_day", 0)),
                weekend_flag=int(row.get("weekend_flag", 0)),
                severity_score=int(row.get("severity_score", 1)),
                event_frequency=int(row.get("event_frequency", 1)),
                malicious_ip_flag=int(row.get("malicious_ip_flag", 0)),
                threat_feed_match=int(row.get("threat_feed_match", 0)),
                cvss_score_final=float(row.get("cvss_score_final", 0.0)),
                alerts_per_user=int(row.get("alerts_per_user", 1))
            )
            events_to_insert.append(evt)

        db.bulk_save_objects(events_to_insert)
        db.commit()
        print(f"[Database] Successfully seeded {len(events_to_insert)} security events into database.")

    except Exception as e:
        db.rollback()
        print(f"[Database Error] Failed to seed database: {e}")
        raise e
    finally:
        db.close()

if __name__ == "__main__":
    init_db(force_reseed=False)
