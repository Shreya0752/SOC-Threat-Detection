import os
import sys
from functools import wraps
from flask import Blueprint, request, jsonify, session
from werkzeug.security import check_password_hash

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.database.db import SessionLocal
from backend.models.database_models import User
from backend.services.event_service import EventService

api_bp = Blueprint("api", __name__)

def db_session():
    return SessionLocal()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or not session.get("user_id"):
            return jsonify({"error": "Unauthorized. Authentication required."}), 401
        return f(*args, **kwargs)
    return decorated_function

# AUTHENTICATION ENDPOINTS

@api_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not username or not password:
        return jsonify({"error": "Invalid username or password"}), 401

    db = db_session()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({"error": "Invalid username or password"}), 401

        # Establish authenticated session
        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = user.role

        return jsonify({
            "message": "Login successful",
            "user": user.to_dict()
        }), 200
    except Exception as e:
        return jsonify({"error": "An error occurred during authentication"}), 500
    finally:
        db.close()

@api_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"}), 200

@api_bp.route("/me", methods=["GET"])
@login_required
def get_current_user():
    return jsonify({
        "user": {
            "id": session.get("user_id"),
            "username": session.get("username"),
            "role": session.get("role", "Tier 2 Security Analyst")
        }
    }), 200

# PROTECTED DASHBOARD TELEMETRY ENDPOINTS

@api_bp.route("/events", methods=["GET"])
@login_required
def get_events():
    db = db_session()
    try:
        severity = request.args.get("severity")
        date = request.args.get("date")
        event_type = request.args.get("event_type")
        ip_address = request.args.get("ip_address") or request.args.get("ip")
        search = request.args.get("search")
        
        try:
            page = int(request.args.get("page", 1))
        except ValueError:
            page = 1

        try:
            limit = int(request.args.get("limit", 50))
        except ValueError:
            limit = 50

        data = EventService.get_events(
            db=db,
            severity=severity,
            date=date,
            event_type=event_type,
            ip_address=ip_address,
            search=search,
            page=page,
            limit=limit
        )
        return jsonify(data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@api_bp.route("/stats", methods=["GET"])
@login_required
def get_stats():
    db = db_session()
    try:
        stats = EventService.get_stats(db)
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@api_bp.route("/threats", methods=["GET"])
@login_required
def get_threats():
    db = db_session()
    try:
        threats = EventService.get_threats(db)
        return jsonify(threats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()
