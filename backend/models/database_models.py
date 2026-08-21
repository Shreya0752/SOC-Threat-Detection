from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(100), default="Tier 2 Security Analyst")

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role
        }

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(50), unique=True, index=True, nullable=False)
    timestamp = Column(String(50), nullable=False)
    source_ip = Column(String(50), index=True)
    destination_ip = Column(String(50), index=True)
    username = Column(String(100), index=True)
    event_type = Column(String(100), index=True)
    protocol = Column(String(50))
    source_country = Column(String(50))
    destination_country = Column(String(50))
    device_name = Column(String(100))
    os = Column(String(100))
    status = Column(String(50))
    severity = Column(String(50), index=True)
    risk_label = Column(String(50), default="Low Risk")
    failed_login_attempts = Column(Integer, default=0)
    malware_detected = Column(String(50), default="No")
    vulnerability_id = Column(String(100))
    cvss_score = Column(Float, default=0.0)
    asset_name = Column(String(100))
    department = Column(String(100))

    # Threat Intel Fields
    threat_indicator = Column(Boolean, default=False)
    threat_match = Column(Boolean, default=False)
    threat_name = Column(String(100), default="No Match")
    threat_actor = Column(String(100), default="Unknown")
    confidence = Column(String(50), default="Unknown")
    threat_severity = Column(String(50), default="None")
    indicator_type = Column(String(50), default="IP Address")

    # MITRE ATT&CK Mapping Fields
    mitre_id = Column(String(50), default="Unknown")
    technique_name = Column(String(100), default="Unknown")
    tactic = Column(String(100), default="Unknown")
    mitre_mapped = Column(Integer, default=0)

    # Asset & Vulnerability Lookups
    asset_type = Column(String(100), default="Unknown")
    owner = Column(String(100), default="Unknown")
    criticality = Column(String(50), default="Unknown")
    vulnerability_name = Column(String(100), default="No Vulnerability")
    patch_available = Column(String(50), default="Unknown")

    # Incident History Lookups
    incident_id = Column(String(50), default="None")
    incident_type = Column(String(100), default="No Incident")
    assigned_to = Column(String(100), default="Unassigned")
    incident_status = Column(String(50), default="Open")

    # Engineered Features
    failed_login_count = Column(Integer, default=0)
    hour_of_day = Column(Integer, default=0)
    weekend_flag = Column(Integer, default=0)
    severity_score = Column(Integer, default=1)
    event_frequency = Column(Integer, default=1)
    malicious_ip_flag = Column(Integer, default=0)
    threat_feed_match = Column(Integer, default=0)
    cvss_score_final = Column(Float, default=0.0)
    alerts_per_user = Column(Integer, default=1)

    def to_dict(self):
        return {
            "id": self.id,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "username": self.username,
            "event_type": self.event_type,
            "protocol": self.protocol,
            "source_country": self.source_country,
            "destination_country": self.destination_country,
            "device_name": self.device_name,
            "os": self.os,
            "status": self.status,
            "severity": self.severity,
            "risk_label": self.risk_label,
            "failed_login_attempts": self.failed_login_attempts,
            "malware_detected": self.malware_detected,
            "vulnerability_id": self.vulnerability_id,
            "cvss_score": self.cvss_score,
            "asset_name": self.asset_name,
            "department": self.department,
            "threat_indicator": self.threat_indicator,
            "threat_match": self.threat_match,
            "threat_name": self.threat_name,
            "threat_actor": self.threat_actor,
            "confidence": self.confidence,
            "threat_severity": self.threat_severity,
            "indicator_type": self.indicator_type,
            "mitre_id": self.mitre_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "mitre_mapped": bool(self.mitre_mapped),
            "asset_type": self.asset_type,
            "owner": self.owner,
            "criticality": self.criticality,
            "vulnerability_name": self.vulnerability_name,
            "patch_available": self.patch_available,
            "incident_id": self.incident_id,
            "incident_type": self.incident_type,
            "assigned_to": self.assigned_to,
            "incident_status": self.incident_status,
            "engineered_features": {
                "failed_login_count": self.failed_login_count,
                "hour_of_day": self.hour_of_day,
                "weekend_flag": self.weekend_flag,
                "severity_score": self.severity_score,
                "event_frequency": self.event_frequency,
                "malicious_ip_flag": self.malicious_ip_flag,
                "threat_feed_match": self.threat_feed_match,
                "cvss_score": self.cvss_score_final,
                "alerts_per_user": self.alerts_per_user
            }
        }

class CleaningStats(Base):
    __tablename__ = "cleaning_stats"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rows_before_cleaning = Column(Integer)
    rows_after_cleaning = Column(Integer)
    duplicates_removed = Column(Integer)
    missing_values_handled = Column(Integer)
    invalid_timestamps_handled = Column(Integer)
    threat_matches = Column(Integer)
    total_events = Column(Integer)
    mitre_mapped_events = Column(Integer)
    mitre_unmapped_events = Column(Integer)
    mitre_mapping_percentage = Column(Float)

class ThreatPrediction(Base):
    __tablename__ = "threat_predictions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(50), index=True, nullable=False, unique=True)
    prediction = Column(String(50), nullable=False)
    threat_type = Column(String(100), default="Unknown")
    confidence_score = Column(Float, default=0.0)
    anomaly_score = Column(Float, default=0.0)
    severity = Column(String(50), default="Low")
    model_version = Column(String(50), default="isolation_forest_v1")
    prediction_timestamp = Column(String(50), nullable=False)
    explanation = Column(String(1000), default="[]")

    def to_dict(self):
        import json
        try:
            reasons = json.loads(self.explanation) if self.explanation else []
        except Exception:
            reasons = [self.explanation] if self.explanation else []

        return {
            "id": self.id,
            "event_id": self.event_id,
            "prediction": self.prediction,
            "threat_type": self.threat_type,
            "confidence_score": self.confidence_score,
            "anomaly_score": self.anomaly_score,
            "severity": self.severity,
            "model_version": self.model_version,
            "prediction_timestamp": self.prediction_timestamp,
            "explanation": reasons
        }


