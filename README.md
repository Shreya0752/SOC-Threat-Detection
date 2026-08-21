# AI-Assisted Threat Detection Dashboard — Milestone 1

## 1. Project Overview
The **AI-Assisted Threat Detection Dashboard** is an enterprise-grade Security Operations Center (SOC) analytics platform designed to aggregate, clean, normalize, enrich, map, and visualize multi-source security telemetry data. 

Milestone 1 establishes the foundational **Security Data Aggregation & Threat Intelligence Layer**, providing data ingestion pipelines, SQLite database storage, Flask REST APIs, and a sleek, interactive dark-mode SOC Analyst Dashboard.

---

## 2. Milestone 1 Objective
The primary objective of Milestone 1 is to:
- Collect security telemetry logs from multiple organizational data sources.
- Clean missing values, drop duplicate records, and standardize timestamps.
- Normalize security event schemas and standardize severity levels into `Critical`, `High`, `Medium`, and `Low`.
- Enrich security events using threat intelligence feeds and rule-based threat indicator triggers (e.g., brute-force login detection and malware infection flags).
- Map security event types against official MITRE ATT&CK techniques and tactics.
- Perform feature engineering to generate ML-ready security features.
- Store all processed security telemetry in an SQLite database using SQLAlchemy ORM.
- Expose RESTful APIs (`GET /events`, `GET /stats`, `GET /threats`) supporting query parameter filtering, pagination, and CORS.
- Provide a high-end SOC Analyst Dashboard with real-time polling updates, KPI cards, threat distribution donut charts, event trend line graphs, top attack type bar charts, and detailed log inspection.

---

## 3. Dataset Descriptions
The system ingests 6 core cybersecurity datasets located in `backend/data/` / `datasets/`:
1. `security_events.csv`: 1,800 raw security event records containing IP addresses, protocols, login attempts, malware flags, and timestamps.
2. `assets.csv`: Asset metadata lookup file containing hostnames, asset types, owners, criticality, and OS information.
3. `vulnerabilities.csv`: Vulnerability feed containing CVE identifiers, CVSS scores, affected assets, and patch availability.
4. `threat_intelligence.csv`: Threat indicator lookup feed with malicious IP addresses, threat actor names, confidence ratings, and severities.
5. `mitre_attack_mapping.csv`: MITRE ATT&CK technique mapping table matching event types to MITRE IDs (e.g., `Failed Login` / `Brute Force` &rarr; `T1110`).
6. `incident_history.csv`: Historic SOC incident tickets linking security events to response times and resolution statuses.

---

## 4. Data Cleaning
The preprocessing pipeline (`backend/preprocessing/pipeline.py`) systematically executes reproducible data cleaning:
- **Duplicates Removal:** Identifies and drops exact duplicate log entries.
- **Missing Values Handling:** Imputes missing strings (`vulnerability_id` &rarr; `"No Vulnerability"`, `username` &rarr; `"unknown_user"`, `asset_name` &rarr; `"Unknown Asset"`), and fills missing numerical fields (failed logins &rarr; `0`, CVSS score &rarr; `0.0`).
- **Timestamp Parsing:** Converts raw timestamp strings into standardized `YYYY-MM-DD HH:MM:SS` format.
- **Data Quality Tracking:** Records exact cleaning metrics into `output/processing_summary.json` and the SQLite `cleaning_stats` table.

---

## 5. Severity Normalization
Raw event severity levels are standardized into four canonical categories:
- `Critical` (maps `critical`, `Critical`, `CRITICAL`)
- `High` (maps `high`, `High`, `HIGH`)
- `Medium` (maps `medium`, `Medium`, `MEDIUM`)
- `Low` (maps `low`, `Low`, `LOW`)

---

## 6. Threat Intelligence Enrichment
Security events are enriched using a dual-layer strategy:
1. **Feed Lookup Matching:** Merges `source_ip` against `indicator_value` in `threat_intelligence.csv`.
2. **Rule-Based Threat Indicators:** Evaluates contextual telemetry rules:
   - `failed_login_attempts >= 5` or `event_type == 'Brute Force'` &rarr; Flags `threat_indicator = True` and sets `threat_name = "Possible Brute Force Attack"`.
   - `malware_detected == 'Yes'` &rarr; Flags `threat_indicator = True` and sets `threat_name = "Malware Infection Alert"`.
3. **Unmatched Event Preservation:** Unmatched events cleanly maintain `threat_match = False` and `threat_name = "No Match"` without fabricating artificial threat indicator data.

---

## 7. MITRE ATT&CK Mapping
Security event types are joined against `mitre_attack_mapping.csv`:
- `Failed Login` / `Brute Force` &rarr; MITRE ID `T1110` (Brute Force), Tactic: `Credential Access`.
- Unmapped events default to `mitre_id = "Unknown"`, `technique_name = "Unknown"`, `tactic = "Unknown"`.
- Mapping statistics (total events, mapped events, unmapped events, mapping percentage) are calculated and exposed via API.

---

## 8. Feature Engineering
The pipeline generates 9 ML-ready security features:
1. **`failed_login_count`**: Integer count of failed authentication attempts.
2. **`hour_of_day`**: Hour extracted from event timestamp (0–23).
3. **`weekend_flag`**: Binary flag (1 for Saturday/Sunday, 0 for weekdays).
4. **`severity_score`**: Numerical rating (`Low = 1`, `Medium = 2`, `High = 3`, `Critical = 4`).
5. **`event_frequency`**: Aggregated volume count for the specific event type.
6. **`malicious_ip_flag`**: Binary flag (1 if source IP matched threat intel feed).
7. **`threat_feed_match`**: Binary indicator of threat feed match.
8. **`cvss_score_final`**: CVSS vulnerability score.
9. **`alerts_per_user`**: Total security events associated with the specific username.

---

## 9. Database Architecture
The backend utilizes SQLite (`backend/database/soc_dashboard.db`) via SQLAlchemy ORM.

### Models:
- **`SecurityEvent`**: Stores normalized telemetry, enriched fields, MITRE tags, lookups, and engineered features.
- **`CleaningStats`**: Stores audit and pipeline cleaning metrics.

---

## 10. Security & Authentication Layer
The platform implements a server-side authentication layer powered by Flask sessions and SQLAlchemy:
- **Password Security:** Passwords are hashed using `werkzeug.security.generate_password_hash` (PBKDF2/SHA-256). No plaintext passwords exist in the database or frontend.
- **Session Management:** Secure HTTP-only cookies (`SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`).
- **Protected APIs:** `@login_required` decorator enforces server-side authentication on `GET /events`, `GET /stats`, `GET /threats`, and `GET /me`. Unauthenticated API requests receive `401 Unauthorized`.
- **Demo Analyst Account:** Configurable via `.env` environment variables (`SOC_ADMIN_USERNAME`, `SOC_ADMIN_PASSWORD`). Default local account: `analyst_admin` / `soc12345`.
- **Session Operations:** `POST /login` establishes session, `POST /logout` clears session.

---

## 11. REST APIs

| Endpoint | Method | Auth Required | Description | Sample Response |
| :--- | :--- | :---: | :--- | :--- |
| `/login` | `POST` | No | Authenticate user credentials | `{"message": "Login successful", "user": {...}}` |
| `/logout` | `POST` | Yes | Destroy active session | `{"message": "Logged out successfully"}` |
| `/me` | `GET` | Yes | Retrieve current session user | `{"user": {"username": "analyst_admin", ...}}` |
| `/events` | `GET` | Yes | Retrieve paginated & filtered security logs | `{"total": 1800, "page": 1, "events": [...]}` |
| `/stats` | `GET` | Yes | Retrieve dynamic SOC dashboard KPIs | `{"total_events": 1800, "critical_events": 346, ...}` |
| `/threats` | `GET` | Yes | Retrieve event type distribution | `[{"event_type": "File Access", "count": 198}, ...]` |
The frontend (`frontend/`) is a dark-mode web application featuring:
- **Authentication:** Professional SOC Analyst Login page (`analyst_admin` / `soc12345`).
- **Sidebar Navigation:** Switch between Overview, Security Events, Threat Intelligence, Vulnerabilities, and Analytics.
- **KPI Cards:** Live counts for Total Events, Critical Threats, High Severity Alerts, Vulnerabilities, and Active Incidents.
- **Threat Distribution Chart:** Interactive Pie/Donut SVG chart.
- **Event Trend Graph:** SVG line graph showing event volume over time.
- **Top Attack Types:** Dynamic horizontal bar chart.
- **Filter Controls:** Instant reactive filtering by Severity, Date, Event Type, IP Address, and Search keyword.
- **Real-Time Polling:** Polling mechanism (5s, 10s, 30s, or Manual) with live status connection pulse badge.

---

## 12. Installation Instructions

### System Requirements:
- Python 3.10+ installed.

### Dependencies Installation:
```bash
pip install -r backend/requirements.txt
```

---

## 13. How to Run the Backend
From the root workspace directory, run:
```bash
python backend/app.py
```
This automatically runs database initialization (`init_db`), seeds the SQLite database from `backend/preprocessing/pipeline.py`, and starts the Flask server on `http://127.0.0.1:5000`.

---

## 14. How to Run the Frontend
The frontend is hosted directly by the backend Flask server at:
```text
http://127.0.0.1:5000/
```
Open your browser to `http://127.0.0.1:5000/` to view the dashboard instantly.

---

## 15. API Endpoints Reference

| Endpoint | Method | Description | Sample Response |
| :--- | :--- | :--- | :--- |
| `/events` | `GET` | Retrieve paginated & filtered security logs | `{"total": 1800, "page": 1, "events": [...]}` |
| `/stats` | `GET` | Retrieve dynamic SOC dashboard KPIs | `{"total_events": 1800, "total_incidents": 1, "active_incidents": 0, "closed_incidents": 1, ...}` |
| `/threats` | `GET` | Retrieve event type distribution | `[{"event_type": "File Access", "count": 198}, ...]` |

---

## 16. Known Limitations
1. **Threat Intel Dataset Size:** The supplied `threat_intelligence.csv` dataset contains 1 reference indicator. Unmatched IPs are preserved as `No Match` without fabricating false malicious matches.
2. **MITRE Coverage:** MITRE mapping relies on supplied `mitre_attack_mapping.csv` rules (179 events mapped). Unmapped events are designated as `Unknown`.
3. **Machine Learning:** Attack detection ML models are out of scope for Milestone 1 and scheduled for Milestone 2.

---

## 17. Milestone 1 Completion Checklist

### Backend Checklist
- [x] Data Collection
- [x] Data Cleaning
- [x] Standard Security Event Schema
- [x] Severity Standardization
- [x] Threat Enrichment
- [x] MITRE Mapping
- [x] Feature Engineering
- [x] Database
- [x] APIs

### Frontend Checklist
- [x] Login Page
- [x] Dashboard
- [x] Sidebar
- [x] KPI Cards
- [x] Event Table
- [x] Threat Distribution Chart
- [x] Event Trend Graph
- [x] Top Attack Types
- [x] Severity Filter
- [x] Date Filter
- [x] Event Type Filter
- [x] IP Address Filter
- [x] API Integration
- [x] Refresh/Real-time Polling Mechanism
