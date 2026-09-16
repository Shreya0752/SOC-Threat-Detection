"""
Incident Repository Module for Milestone 3 (`backend/database/incident_repository.py`).
Implements persistence for M3 Incident records into MongoDB 'incidents' collection.
Includes automatic detection of MongoDB availability and robust local SQLite fallback
with transparent status reporting if MongoDB is not accessible.
"""
import os
import sys
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sqlalchemy import Column, Integer, String, Float, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.database.db import DB_PATH

Base = declarative_base()

class IncidentFallbackModel(Base):
    __tablename__ = "incidents_fallback"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(50), unique=True, index=True, nullable=False)
    threat_type = Column(String(100), nullable=False)
    risk_score = Column(Integer, default=0)
    priority = Column(String(50), default="Low")
    asset_id = Column(String(100), default="Unknown")
    department = Column(String(100), default="IT")
    affected_user = Column(String(100), default="Unknown")
    mitre_technique = Column(String(100), default="Unknown")
    status = Column(String(50), default="Open")
    created_at = Column(String(50), nullable=False)
    event_ids_json = Column(Text, default="[]")
    recommendation_json = Column(Text, default="[]")
    risk_factors_json = Column(Text, default="{}")
    attack_chain_json = Column(Text, default="[]")
    explainability_json = Column(Text, default="[]")
    status_history_json = Column(Text, default="[]")
    status_updated_at = Column(String(50), default="")
    analyst_feedback = Column(String(50), default="Unassigned")
    feedback_notes = Column(Text, default="")
    feedback_analyst = Column(String(100), default="")
    feedback_timestamp = Column(String(50), default="")

    def to_dict(self) -> Dict[str, Any]:
        try:
            event_ids = json.loads(self.event_ids_json) if self.event_ids_json else []
        except Exception:
            event_ids = []
        try:
            rec = json.loads(self.recommendation_json) if self.recommendation_json else []
        except Exception:
            rec = []
        try:
            factors = json.loads(self.risk_factors_json) if self.risk_factors_json else {}
        except Exception:
            factors = {}
        try:
            chain = json.loads(self.attack_chain_json) if self.attack_chain_json else []
        except Exception:
            chain = []
        try:
            exp = json.loads(self.explainability_json) if self.explainability_json else []
        except Exception:
            exp = []
        try:
            history = json.loads(self.status_history_json) if self.status_history_json else []
        except Exception:
            history = []

        return {
            "incident_id": self.incident_id,
            "threat_type": self.threat_type,
            "risk_score": self.risk_score,
            "priority": self.priority,
            "asset_id": self.asset_id,
            "department": self.department or "IT",
            "affected_user": self.affected_user,
            "mitre_technique": self.mitre_technique,
            "status": self.status,
            "created_at": self.created_at,
            "event_ids": event_ids,
            "recommendation": rec,
            "risk_factors": factors,
            "explainability": exp,
            "attack_chain": chain,
            "status_history": history,
            "status_updated_at": self.status_updated_at or "",
            "analyst_feedback": self.analyst_feedback or "Unassigned",
            "feedback_notes": self.feedback_notes or "",
            "feedback_analyst": self.feedback_analyst or "",
            "feedback_timestamp": self.feedback_timestamp or ""
        }

class SystemConfigFallbackModel(Base):
    __tablename__ = "system_config"

    key = Column(String(100), primary_key=True)
    value_json = Column(Text, default="{}")
    updated_at = Column(String(50), nullable=False)

class IncidentRepository:
    """
    Manages persistence of M3 Incidents to MongoDB ('incidents' collection),
    with clear diagnostic reporting, system configuration persistence,
    analyst workflows, and robust fallback handling.
    """
    _mongo_client = None
    _mongo_db = None
    _mongo_collection = None
    _is_connected = False
    _fallback_engine = None
    _FallbackSession = None

    @classmethod
    def initialize(cls):
        """Initializes connection to MongoDB, falling back if unavailable."""
        mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        db_name = os.getenv("MONGODB_DB_NAME", "soc_threatdetect")

        try:
            import pymongo
            client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=1500)
            # Ping to verify active connection
            client.admin.command('ping')
            cls._mongo_client = client
            cls._mongo_db = client[db_name]
            cls._mongo_collection = cls._mongo_db["incidents"]
            cls._is_connected = True
            print(f"[IncidentRepository] Successfully connected to MongoDB at {mongo_uri} (Database: {db_name}).")
        except Exception as e:
            cls._is_connected = False
            if 'client' in locals() and client:
                try:
                    client.close()
                except Exception:
                    pass
            print(f"[IncidentRepository Warning] MongoDB is unavailable at {mongo_uri} ({str(e)}). "
                  f"Utilizing local SQLite 'incidents_fallback' persistence table.")

        # Always initialize fallback SQLite table
        fallback_uri = f"sqlite:///{DB_PATH}"
        cls._fallback_engine = create_engine(fallback_uri, echo=False, connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=cls._fallback_engine)

        # Ensure incidents_fallback schema contains all extended columns
        with cls._fallback_engine.connect() as conn:
            cursor = conn.exec_driver_sql("PRAGMA table_info(incidents_fallback)")
            cols = [row[1] for row in cursor.fetchall()]
            extra_cols = {
                "department": "TEXT DEFAULT 'IT'",
                "explainability_json": "TEXT DEFAULT '[]'",
                "status_history_json": "TEXT DEFAULT '[]'",
                "status_updated_at": "VARCHAR(50) DEFAULT ''",
                "analyst_feedback": "VARCHAR(50) DEFAULT 'Unassigned'",
                "feedback_notes": "TEXT DEFAULT ''",
                "feedback_analyst": "VARCHAR(100) DEFAULT ''",
                "feedback_timestamp": "VARCHAR(50) DEFAULT ''"
            }
            for col_name, col_type in extra_cols.items():
                if cols and col_name not in cols:
                    try:
                        conn.exec_driver_sql(f"ALTER TABLE incidents_fallback ADD COLUMN {col_name} {col_type}")
                    except Exception as e:
                        print(f"[IncidentRepository Warning] Could not alter column {col_name}: {e}")
            conn.commit()

        cls._FallbackSession = sessionmaker(autocommit=False, autoflush=False, bind=cls._fallback_engine)

    @classmethod
    def get_connectivity_status(cls) -> Dict[str, Any]:
        """Returns current database connectivity and persistence telemetry."""
        if cls._fallback_engine is None:
            cls.initialize()
        return {
            "is_mongodb_connected": cls._is_connected,
            "storage_engine": "MongoDB (incidents collection)" if cls._is_connected else "SQLite fallback (incidents_fallback)",
            "mongodb_uri": os.getenv("MONGODB_URI", "mongodb://localhost:27017"),
            "status_message": "Active MongoDB Connection" if cls._is_connected else "MongoDB server unreachable on localhost:27017. Storing data in persistent fallback repository."
        }

    @classmethod
    def save_risk_weights(cls, weights: Dict[str, float]) -> Dict[str, float]:
        """Persists updated risk calculation weights in MongoDB system_config or SQLite."""
        if cls._fallback_engine is None:
            cls.initialize()

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if cls._is_connected and cls._mongo_db is not None:
            try:
                cls._mongo_db["system_config"].update_one(
                    {"config_key": "risk_weights"},
                    {"$set": {"config_key": "risk_weights", "weights": weights, "updated_at": now_str}},
                    upsert=True
                )
            except Exception as e:
                print(f"[IncidentRepository Error] MongoDB save_risk_weights failed: {e}")

        session = cls._FallbackSession()
        try:
            row = session.query(SystemConfigFallbackModel).filter(SystemConfigFallbackModel.key == "risk_weights").first()
            if row:
                row.value_json = json.dumps(weights)
                row.updated_at = now_str
            else:
                new_row = SystemConfigFallbackModel(key="risk_weights", value_json=json.dumps(weights), updated_at=now_str)
                session.add(new_row)
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"[IncidentRepository Error] SQLite save_risk_weights failed: {e}")
        finally:
            session.close()

        return weights

    @classmethod
    def get_risk_weights(cls) -> Optional[Dict[str, float]]:
        """Loads persisted risk calculation weights, or returns None if not set."""
        if cls._fallback_engine is None:
            cls.initialize()

        if cls._is_connected and cls._mongo_db is not None:
            try:
                doc = cls._mongo_db["system_config"].find_one({"config_key": "risk_weights"}, {"_id": 0})
                if doc and "weights" in doc:
                    return doc["weights"]
            except Exception as e:
                print(f"[IncidentRepository Error] MongoDB get_risk_weights failed: {e}")

        session = cls._FallbackSession()
        try:
            row = session.query(SystemConfigFallbackModel).filter(SystemConfigFallbackModel.key == "risk_weights").first()
            if row and row.value_json:
                return json.loads(row.value_json)
            return None
        except Exception:
            return None
        finally:
            session.close()

    @classmethod
    def save_incident(cls, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Inserts or updates an incident record idempotently."""
        if cls._fallback_engine is None:
            cls.initialize()

        inc_copy = dict(incident)
        inc_id = inc_copy.get("incident_id")
        if not inc_id:
            raise ValueError("Incident must include 'incident_id'.")

        if cls._is_connected and cls._mongo_collection is not None:
            try:
                # MongoDB Upsert
                cls._mongo_collection.update_one(
                    {"incident_id": inc_id},
                    {"$set": inc_copy},
                    upsert=True
                )
                inc_copy.pop("_id", None)
                return inc_copy
            except Exception as e:
                print(f"[IncidentRepository Error] MongoDB write failed ({str(e)}). Writing to fallback...")

        # Fallback persistence
        session = cls._FallbackSession()
        try:
            existing = session.query(IncidentFallbackModel).filter(IncidentFallbackModel.incident_id == inc_id).first()
            if existing:
                existing.threat_type = inc_copy.get("threat_type", existing.threat_type)
                existing.risk_score = inc_copy.get("risk_score", existing.risk_score)
                existing.priority = inc_copy.get("priority", existing.priority)
                existing.asset_id = inc_copy.get("asset_id", existing.asset_id)
                existing.department = inc_copy.get("department", existing.department or "IT")
                existing.affected_user = inc_copy.get("affected_user", existing.affected_user)
                existing.mitre_technique = inc_copy.get("mitre_technique", existing.mitre_technique)
                existing.status = inc_copy.get("status", existing.status)
                existing.created_at = inc_copy.get("created_at", existing.created_at)
                existing.event_ids_json = json.dumps(inc_copy.get("event_ids", []))
                existing.recommendation_json = json.dumps(inc_copy.get("recommendation", []))
                existing.risk_factors_json = json.dumps(inc_copy.get("risk_factors", {}))
                existing.attack_chain_json = json.dumps(inc_copy.get("attack_chain", []))
                existing.explainability_json = json.dumps(inc_copy.get("explainability", []))
                if "status_history" in inc_copy:
                    existing.status_history_json = json.dumps(inc_copy["status_history"])
                if "status_updated_at" in inc_copy:
                    existing.status_updated_at = inc_copy["status_updated_at"]
                if "analyst_feedback" in inc_copy:
                    existing.analyst_feedback = inc_copy["analyst_feedback"]
                if "feedback_notes" in inc_copy:
                    existing.feedback_notes = inc_copy["feedback_notes"]
                if "feedback_analyst" in inc_copy:
                    existing.feedback_analyst = inc_copy["feedback_analyst"]
                if "feedback_timestamp" in inc_copy:
                    existing.feedback_timestamp = inc_copy["feedback_timestamp"]
            else:
                new_row = IncidentFallbackModel(
                    incident_id=inc_id,
                    threat_type=inc_copy.get("threat_type", "Unknown"),
                    risk_score=inc_copy.get("risk_score", 0),
                    priority=inc_copy.get("priority", "Low"),
                    asset_id=inc_copy.get("asset_id", "Unknown"),
                    department=inc_copy.get("department", "IT"),
                    affected_user=inc_copy.get("affected_user", "Unknown"),
                    mitre_technique=inc_copy.get("mitre_technique", "Unknown"),
                    status=inc_copy.get("status", "Open"),
                    created_at=inc_copy.get("created_at", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
                    event_ids_json=json.dumps(inc_copy.get("event_ids", [])),
                    recommendation_json=json.dumps(inc_copy.get("recommendation", [])),
                    risk_factors_json=json.dumps(inc_copy.get("risk_factors", {})),
                    attack_chain_json=json.dumps(inc_copy.get("attack_chain", [])),
                    explainability_json=json.dumps(inc_copy.get("explainability", [])),
                    status_history_json=json.dumps(inc_copy.get("status_history", [])),
                    status_updated_at=inc_copy.get("status_updated_at", ""),
                    analyst_feedback=inc_copy.get("analyst_feedback", "Unassigned"),
                    feedback_notes=inc_copy.get("feedback_notes", ""),
                    feedback_analyst=inc_copy.get("feedback_analyst", ""),
                    feedback_timestamp=inc_copy.get("feedback_timestamp", "")
                )
                session.add(new_row)
            session.commit()
            return inc_copy
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    @classmethod
    def get_incident_by_id(cls, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single incident by its unique incident_id."""
        if cls._fallback_engine is None:
            cls.initialize()

        if cls._is_connected and cls._mongo_collection is not None:
            try:
                record = cls._mongo_collection.find_one({"incident_id": incident_id}, {"_id": 0})
                if record:
                    return record
            except Exception as e:
                print(f"[IncidentRepository Error] MongoDB read failed ({str(e)}). Falling back...")

        session = cls._FallbackSession()
        try:
            row = session.query(IncidentFallbackModel).filter(IncidentFallbackModel.incident_id == incident_id).first()
            if row:
                return row.to_dict()
            return None
        finally:
            session.close()

    @classmethod
    def get_incidents(cls,
                      priority: Optional[str] = None,
                      threat_type: Optional[str] = None,
                      asset_id: Optional[str] = None,
                      department: Optional[str] = None,
                      mitre_technique: Optional[str] = None,
                      ioc_status: Optional[str] = None,
                      status: Optional[str] = None,
                      search: Optional[str] = None,
                      date_from: Optional[str] = None,
                      date_to: Optional[str] = None,
                      sort_by: str = "risk_score",
                      sort_order: str = "desc",
                      page: int = 1,
                      limit: int = 25) -> Dict[str, Any]:
        """
        Retrieves paginated and filtered incidents, supporting multi-criteria sorting and filtering.
        """
        if cls._fallback_engine is None:
            cls.initialize()

        # Map sorting key
        valid_sort_keys = ["risk_score", "created_at", "priority", "asset_id", "status"]
        sort_col = sort_by if sort_by in valid_sort_keys else "risk_score"
        sort_dir = -1 if str(sort_order).lower() == "desc" else 1

        # Try MongoDB
        if cls._is_connected and cls._mongo_collection is not None:
            try:
                query = {}
                if priority and priority.lower() != "all":
                    query["priority"] = {"$regex": f"^{priority}$", "$options": "i"}
                if threat_type and threat_type.lower() != "all":
                    query["threat_type"] = {"$regex": threat_type, "$options": "i"}
                if asset_id and asset_id.lower() != "all":
                    query["asset_id"] = {"$regex": asset_id, "$options": "i"}
                if department and department.lower() != "all":
                    query["department"] = {"$regex": department, "$options": "i"}
                if mitre_technique and mitre_technique.lower() != "all":
                    query["$or"] = [
                        {"mitre_technique": {"$regex": mitre_technique, "$options": "i"}},
                        {"attack_chain.mitre_id": {"$regex": mitre_technique, "$options": "i"}}
                    ]
                if ioc_status and ioc_status.lower() == "malicious":
                    query["risk_factors.threat_intelligence.raw"] = {"$gt": 0}
                if status and status.lower() != "all":
                    query["status"] = {"$regex": f"^{status}$", "$options": "i"}

                if date_from or date_to:
                    date_query = {}
                    if date_from:
                        date_query["$gte"] = str(date_from)
                    if date_to:
                        date_query["$lte"] = str(date_to)
                    query["created_at"] = date_query

                if search and search.strip():
                    pattern = search.strip()
                    search_clause = [
                        {"incident_id": {"$regex": pattern, "$options": "i"}},
                        {"threat_type": {"$regex": pattern, "$options": "i"}},
                        {"asset_id": {"$regex": pattern, "$options": "i"}},
                        {"affected_user": {"$regex": pattern, "$options": "i"}},
                        {"department": {"$regex": pattern, "$options": "i"}}
                    ]
                    if "$or" in query:
                        query["$and"] = [{"$or": query.pop("$or")}, {"$or": search_clause}]
                    else:
                        query["$or"] = search_clause

                total = cls._mongo_collection.count_documents(query)
                cursor = cls._mongo_collection.find(query, {"_id": 0})\
                                              .sort(sort_col, sort_dir)

                if limit > 0:
                    cursor = cursor.skip((page - 1) * limit).limit(limit)

                return {
                    "total": total,
                    "page": page,
                    "limit": limit,
                    "incidents": list(cursor)
                }
            except Exception as e:
                print(f"[IncidentRepository Error] MongoDB query failed ({str(e)}). Falling back...")

        # Fallback SQLite implementation
        session = cls._FallbackSession()
        try:
            q = session.query(IncidentFallbackModel)
            if priority and priority.lower() != "all":
                q = q.filter(IncidentFallbackModel.priority.ilike(priority))
            if threat_type and threat_type.lower() != "all":
                q = q.filter(IncidentFallbackModel.threat_type.ilike(f"%{threat_type}%"))
            if asset_id and asset_id.lower() != "all":
                q = q.filter(IncidentFallbackModel.asset_id.ilike(f"%{asset_id}%"))
            if department and department.lower() != "all":
                q = q.filter(IncidentFallbackModel.department.ilike(f"%{department}%"))
            if mitre_technique and mitre_technique.lower() != "all":
                q = q.filter(IncidentFallbackModel.mitre_technique.ilike(f"%{mitre_technique}%"))
            if status and status.lower() != "all":
                q = q.filter(IncidentFallbackModel.status.ilike(status))
            if date_from:
                q = q.filter(IncidentFallbackModel.created_at >= str(date_from))
            if date_to:
                q = q.filter(IncidentFallbackModel.created_at <= str(date_to))

            if search and search.strip():
                pattern = f"%{search.strip()}%"
                from sqlalchemy import or_
                q = q.filter(
                    or_(
                        IncidentFallbackModel.incident_id.ilike(pattern),
                        IncidentFallbackModel.threat_type.ilike(pattern),
                        IncidentFallbackModel.asset_id.ilike(pattern),
                        IncidentFallbackModel.affected_user.ilike(pattern),
                        IncidentFallbackModel.department.ilike(pattern)
                    )
                )

            total = q.count()

            # Dynamic order by
            col_attr = getattr(IncidentFallbackModel, sort_col, IncidentFallbackModel.risk_score)
            if sort_dir == -1:
                q = q.order_by(col_attr.desc())
            else:
                q = q.order_by(col_attr.asc())

            if limit > 0:
                rows = q.offset((page - 1) * limit).limit(limit).all()
            else:
                rows = q.all()

            return {
                "total": total,
                "page": page,
                "limit": limit,
                "incidents": [r.to_dict() for r in rows]
            }
        finally:
            session.close()

    @classmethod
    def update_incident_status(cls, incident_id: str, new_status: str, analyst: str = "SOC Analyst", notes: str = "") -> bool:
        """Updates investigation status of an incident and appends an audit history entry."""
        valid_statuses = ["Open", "Investigating", "Resolved", "False Positive"]
        matched_status = next((s for s in valid_statuses if s.lower() == new_status.strip().lower()), None)
        if not matched_status:
            return False

        if cls._fallback_engine is None:
            cls.initialize()

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Fetch current status for history
        current_status = "Open"
        existing = cls.get_incident_by_id(incident_id)
        if existing:
            current_status = existing.get("status", "Open")

        history_entry = {
            "from_status": current_status,
            "to_status": matched_status,
            "changed_at": now_str,
            "analyst": analyst,
            "notes": notes or ""
        }

        updated_mongo = False
        if cls._is_connected and cls._mongo_collection is not None:
            try:
                res = cls._mongo_collection.update_one(
                    {"incident_id": incident_id},
                    {
                        "$set": {
                            "status": matched_status,
                            "status_updated_at": now_str
                        },
                        "$push": {
                            "status_history": history_entry
                        }
                    }
                )
                updated_mongo = res.modified_count > 0 or res.matched_count > 0
            except Exception as e:
                print(f"[IncidentRepository Error] Mongo update status failed: {e}")

        session = cls._FallbackSession()
        try:
            row = session.query(IncidentFallbackModel).filter(IncidentFallbackModel.incident_id == incident_id).first()
            if row:
                row.status = matched_status
                row.status_updated_at = now_str
                try:
                    hist = json.loads(row.status_history_json) if row.status_history_json else []
                except Exception:
                    hist = []
                hist.append(history_entry)
                row.status_history_json = json.dumps(hist)
                session.commit()
                return True
            return updated_mongo
        except Exception:
            session.rollback()
            return updated_mongo
        finally:
            session.close()

    @classmethod
    def save_analyst_feedback(cls, incident_id: str, feedback: str, notes: str = "", analyst: str = "SOC Analyst") -> bool:
        """Persists analyst feedback (True Positive, False Positive, Needs Review) without altering M2 predictions."""
        valid_feedback = ["True Positive", "False Positive", "Needs Review"]
        matched_feedback = next((f for f in valid_feedback if f.lower() == feedback.strip().lower()), None)
        if not matched_feedback:
            return False

        if cls._fallback_engine is None:
            cls.initialize()

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        updated_mongo = False
        if cls._is_connected and cls._mongo_collection is not None:
            try:
                res = cls._mongo_collection.update_one(
                    {"incident_id": incident_id},
                    {
                        "$set": {
                            "analyst_feedback": matched_feedback,
                            "feedback_notes": notes or "",
                            "feedback_analyst": analyst,
                            "feedback_timestamp": now_str
                        }
                    }
                )
                updated_mongo = res.modified_count > 0 or res.matched_count > 0
            except Exception as e:
                print(f"[IncidentRepository Error] Mongo save_analyst_feedback failed: {e}")

        session = cls._FallbackSession()
        try:
            row = session.query(IncidentFallbackModel).filter(IncidentFallbackModel.incident_id == incident_id).first()
            if row:
                row.analyst_feedback = matched_feedback
                row.feedback_notes = notes or ""
                row.feedback_analyst = analyst
                row.feedback_timestamp = now_str
                session.commit()
                return True
            return updated_mongo
        except Exception:
            session.rollback()
            return updated_mongo
        finally:
            session.close()

    @classmethod
    def count_incidents(cls) -> int:
        """Returns total count of stored incidents."""
        if cls._fallback_engine is None:
            cls.initialize()

        if cls._is_connected and cls._mongo_collection is not None:
            try:
                return cls._mongo_collection.count_documents({})
            except Exception:
                pass

        session = cls._FallbackSession()
        try:
            return session.query(IncidentFallbackModel).count()
        finally:
            session.close()

