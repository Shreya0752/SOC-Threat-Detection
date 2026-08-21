import os
import sys
from dotenv import load_dotenv
from flask import Flask, send_from_directory, jsonify, request, session
from flask_cors import CORS

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

from backend.database.db import init_db
from backend.routes.api import api_bp
from backend.routes.prediction_routes import pred_bp
from backend.routes.anomaly_routes import anomaly_bp
from backend.routes.analytics_routes import analytics_bp

app = Flask(__name__, static_folder="../frontend", static_url_path="")

# Configure session secret key & security settings
app.secret_key = os.getenv("SECRET_KEY", "soc-threatdetect-secret-key-2026-production")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Enable CORS with credentials support for session cookies
CORS(app, supports_credentials=True)

# Register API Blueprints (M1 & M2 Routes)
app.register_blueprint(api_bp)
app.register_blueprint(pred_bp)
app.register_blueprint(anomaly_bp)
app.register_blueprint(analytics_bp)

# Proxy routes for /api/* endpoints
@app.route("/api/<path:endpoint>", methods=["GET", "POST"])
def api_proxy(endpoint):
    from flask import redirect, url_for
    if endpoint == "login":
        return redirect(url_for("api.login"), code=307)
    elif endpoint == "logout":
        return redirect(url_for("api.logout"), code=307)
    elif endpoint == "me":
        return redirect(url_for("api.get_current_user"))
    elif endpoint == "events":
        return redirect(url_for("api.get_events", **request.args))
    elif endpoint == "stats":
        return redirect(url_for("api.get_stats", **request.args))
    elif endpoint == "threats":
        return redirect(url_for("api.get_threats", **request.args))
    elif endpoint == "predict":
        return redirect(url_for("prediction_routes.predict_event", **request.args), code=307)
    elif endpoint == "predictions":
        return redirect(url_for("prediction_routes.get_predictions", **request.args))
    elif endpoint.startswith("predictions/"):
        evt_id = endpoint.split("predictions/")[1]
        return redirect(url_for("prediction_routes.get_prediction_by_id", event_id=evt_id))
    elif endpoint == "anomalies":
        return redirect(url_for("prediction_routes.get_anomalies", **request.args))
    elif endpoint == "model-performance":
        return redirect(url_for("prediction_routes.get_model_performance"))
    elif endpoint == "threat-summary":
        return redirect(url_for("prediction_routes.get_threat_summary"))
    return jsonify({"error": "Unknown API endpoint"}), 404

@app.route("/")
def serve_frontend():
    return send_from_directory(app.static_folder, "index.html")

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api") or request.path in ["/events", "/stats", "/threats", "/me", "/login", "/logout"]:
        return jsonify({"error": "Endpoint not found"}), 404
    return send_from_directory(app.static_folder, "index.html")

if __name__ == "__main__":
    print("[App] Initializing Database...")
    init_db(force_reseed=False)
    print("[App] Starting Flask Server on http://127.0.0.1:5000...")
    app.run(host="0.0.0.0", port=5000, debug=True)
