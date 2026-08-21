import os
import sys
from sqlalchemy import func, or_
from backend.models.database_models import SecurityEvent, CleaningStats

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

class EventService:
    @staticmethod
    def get_events(db, severity=None, date=None, event_type=None, ip_address=None, search=None, page=1, limit=50):
        """
        Retrieves filtered and paginated security events from the database.
        Supports case-insensitive search across Username, Device Name, Asset Name, and Event ID.
        """
        query = db.query(SecurityEvent)

        if severity and severity.lower() != "all":
            query = query.filter(func.lower(SecurityEvent.severity) == severity.lower())

        if date:
            query = query.filter(SecurityEvent.timestamp.like(f"{date}%"))

        if event_type and event_type.lower() != "all":
            query = query.filter(func.lower(SecurityEvent.event_type) == event_type.lower())

        if ip_address:
            query = query.filter(
                or_(
                    SecurityEvent.source_ip.like(f"%{ip_address}%"),
                    SecurityEvent.destination_ip.like(f"%{ip_address}%")
                )
            )

        if search and search.strip():
            search_str = search.strip()
            search_pattern = f"%{search_str}%"
            query = query.filter(
                or_(
                    func.lower(SecurityEvent.username).like(func.lower(search_pattern)),
                    func.lower(SecurityEvent.event_id).like(func.lower(search_pattern)),
                    func.lower(SecurityEvent.device_name).like(func.lower(search_pattern)),
                    func.lower(SecurityEvent.asset_name).like(func.lower(search_pattern)),
                    func.lower(SecurityEvent.source_ip).like(func.lower(search_pattern)),
                    func.lower(SecurityEvent.event_type).like(func.lower(search_pattern))
                )
            )

        total_count = query.count()

        # Sort descending by timestamp / id
        query = query.order_by(SecurityEvent.id.desc())

        # Pagination
        if limit > 0:
            offset = (page - 1) * limit
            events = query.offset(offset).limit(limit).all()
        else:
            events = query.all()

        return {
            "total": total_count,
            "page": page,
            "limit": limit,
            "events": [evt.to_dict() for evt in events]
        }

    @staticmethod
    def get_stats(db):
        """
        Computes dynamic dashboard statistics from the database.
        """
        total_events = db.query(SecurityEvent).count()
        critical_events = db.query(SecurityEvent).filter(func.lower(SecurityEvent.severity) == "critical").count()
        high_events = db.query(SecurityEvent).filter(func.lower(SecurityEvent.severity) == "high").count()
        medium_events = db.query(SecurityEvent).filter(func.lower(SecurityEvent.severity) == "medium").count()
        low_events = db.query(SecurityEvent).filter(func.lower(SecurityEvent.severity) == "low").count()

        vulnerabilities = db.query(SecurityEvent).filter(
            SecurityEvent.vulnerability_id.isnot(None),
            SecurityEvent.vulnerability_id != "No Vulnerability",
            SecurityEvent.vulnerability_id != "None"
        ).count()

        # Incident Statistics (calculated strictly from actual matching incident records)
        total_incidents = db.query(SecurityEvent).filter(
            SecurityEvent.incident_id.isnot(None),
            SecurityEvent.incident_id != "None",
            SecurityEvent.incident_id != "nan"
        ).count()

        active_incidents = db.query(SecurityEvent).filter(
            SecurityEvent.incident_id.isnot(None),
            SecurityEvent.incident_id != "None",
            SecurityEvent.incident_id != "nan",
            func.lower(SecurityEvent.incident_status) != "closed",
            func.lower(SecurityEvent.incident_status) != "resolved"
        ).count()

        closed_incidents = db.query(SecurityEvent).filter(
            SecurityEvent.incident_id.isnot(None),
            SecurityEvent.incident_id != "None",
            SecurityEvent.incident_id != "nan",
            or_(
                func.lower(SecurityEvent.incident_status) == "closed",
                func.lower(SecurityEvent.incident_status) == "resolved"
            )
        ).count()

        malware_events = db.query(SecurityEvent).filter(
            func.lower(SecurityEvent.malware_detected) == "yes"
        ).count()

        mitre_mapped = db.query(SecurityEvent).filter(SecurityEvent.mitre_mapped == 1).count()
        threat_matches = db.query(SecurityEvent).filter(SecurityEvent.threat_match == True).count()

        # Retrieve cleaning stats if stored
        cleaning_record = db.query(CleaningStats).first()
        cleaning_info = {}
        if cleaning_record:
            cleaning_info = {
                "rows_before_cleaning": cleaning_record.rows_before_cleaning,
                "rows_after_cleaning": cleaning_record.rows_after_cleaning,
                "duplicates_removed": cleaning_record.duplicates_removed,
                "missing_values_handled": cleaning_record.missing_values_handled,
                "invalid_timestamps_handled": cleaning_record.invalid_timestamps_handled
            }

        return {
            "total_events": total_events,
            "critical_events": critical_events,
            "high_events": high_events,
            "medium_events": medium_events,
            "low_events": low_events,
            "vulnerabilities": vulnerabilities,
            "total_incidents": total_incidents,
            "active_incidents": active_incidents,
            "closed_incidents": closed_incidents,
            "malware_events": malware_events,
            "threat_matches": threat_matches,
            "mitre_mapped_events": mitre_mapped,
            "mitre_mapping_percentage": round((mitre_mapped / total_events) * 100, 2) if total_events > 0 else 0.0,
            "cleaning_stats": cleaning_info
        }

    @staticmethod
    def get_threats(db):
        """
        Aggregates event type count distributions from the database.
        """
        results = db.query(
            SecurityEvent.event_type,
            func.count(SecurityEvent.id).label("count")
        ).group_by(SecurityEvent.event_type).order_by(func.count(SecurityEvent.id).desc()).all()

        return [
            {"event_type": row.event_type, "count": row.count}
            for row in results
        ]
