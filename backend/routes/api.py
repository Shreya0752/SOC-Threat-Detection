import os
import sys
from functools import wraps
from flask import Blueprint, request, jsonify, session
from werkzeug.security import check_password_hash, generate_password_hash

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
    db = db_session()
    try:
        user_id = session.get("user_id")
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            return jsonify({
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role or "Tier 2 Security Analyst"
                }
            }), 200
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@api_bp.route("/profile/update-username", methods=["POST"])
@login_required
def update_username():
    data = request.get_json(silent=True) or {}
    new_username = str(data.get("new_username", "")).strip()

    if not new_username:
        return jsonify({"error": "New username cannot be empty."}), 400

    db = db_session()
    try:
        user_id = session.get("user_id")
        # Check if username is already taken by another user
        exists = db.query(User).filter(User.username == new_username, User.id != user_id).first()
        if exists:
            return jsonify({"error": "Username is already taken."}), 400

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "User not found."}), 404

        user.username = new_username
        db.commit()

        # Update session
        session["username"] = new_username

        return jsonify({
            "message": "Username updated successfully.",
            "user": user.to_dict()
        }), 200
    except Exception as e:
        db.rollback()
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
    finally:
        db.close()

@api_bp.route("/profile/update-password", methods=["POST"])
@login_required
def update_password():
    data = request.get_json(silent=True) or {}
    current_password = str(data.get("current_password", "")).strip()
    new_password = str(data.get("new_password", "")).strip()
    confirm_password = str(data.get("confirm_password", "")).strip()

    if not current_password or not new_password or not confirm_password:
        return jsonify({"error": "All password fields are required."}), 400

    if new_password != confirm_password:
        return jsonify({"error": "New passwords do not match."}), 400

    db = db_session()
    try:
        user_id = session.get("user_id")
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "User not found."}), 404

        if not check_password_hash(user.password_hash, current_password):
            return jsonify({"error": "Incorrect current password."}), 400

        user.password_hash = generate_password_hash(new_password)
        db.commit()

        return jsonify({"message": "Password updated successfully."}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
    finally:
        db.close()

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

@api_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()
    confirm_password = str(data.get("confirm_password", "")).strip()

    if not email or not username or not password or not confirm_password:
        return jsonify({"error": "All fields (EMAIL, USERNAME, PASSWORD, CONFIRM PASSWORD) are required."}), 400

    if "@" not in email or "." not in email:
        return jsonify({"error": "Please enter a valid EMAIL address."}), 400

    if len(username) < 3 or " " in username:
        return jsonify({"error": "USERNAME must be at least 3 characters long and contain no spaces."}), 400

    if password != confirm_password:
        return jsonify({"error": "Passwords do not match."}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters long."}), 400

    db = db_session()
    try:
        # Check uniqueness
        dup_user = db.query(User).filter(User.username == username).first()
        if dup_user:
            return jsonify({"error": "USERNAME is already registered."}), 400

        dup_email = db.query(User).filter(User.email == email).first()
        if dup_email:
            return jsonify({"error": "EMAIL is already registered."}), 400

        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role="Tier 2 Security Analyst"
        )
        db.add(new_user)
        db.commit()

        return jsonify({
            "message": "Account created successfully. You can now login.",
            "user": new_user.to_dict()
        }), 201
    except Exception as e:
        return jsonify({"error": f"An error occurred during account creation: {str(e)}"}), 500
    finally:
        db.close()

@api_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip()

    if not username and not email:
        return jsonify({"error": "USERNAME or EMAIL is required."}), 400

    # Professional directive without claiming email sent or revealing password:
    return jsonify({
        "message": "Password recovery is restricted. Please contact your SOC System Administrator to reset your credentials."
    }), 200

