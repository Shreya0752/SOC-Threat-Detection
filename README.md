# SOC ThreatDetect AI — AI-Assisted Security Operations Center

## 1. Project Overview
The **SOC ThreatDetect AI** platform is an enterprise-grade Security Operations Center (SOC) analytics and threat intelligence system. It combines multi-source security telemetry aggregation, cleaning, normalization, enrichment, and visualization (Milestone 1) with an unsupervised Machine Learning engine for anomaly detection, rule-assisted threat classification, and risk scoring (Milestone 2).

The system operates across two core layers:
- **Milestone 1 — Security Data Aggregation & Threat Intelligence Layer:** Ingests raw telemetry logs, cleans missing and duplicate records, standardizes severities, enriches events with threat intelligence IOC feeds, maps event types to MITRE ATT&CK techniques, computes engineered security features, and stores normalized data in an SQLite database accessible via Flask REST APIs and an interactive dark-mode dashboard.
- **Milestone 2 — AI Threat Detection & Anomaly Analysis Layer:** Extracts engineered feature vectors, scales and encodes numerical/categorical attributes, performs unsupervised anomaly detection using an Isolation Forest model (`isolation_forest_v1.pkl`), executes deterministic threat classification and confidence scoring, persists prediction records in the database (`threat_predictions` table), exposes dedicated M2 REST APIs, and provides an AI Threat Detection frontend interface with interactive risk charts and event investigation tools.

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
- Expose RESTful APIs (`GET /events`, `GET /stats`, `GET /threats`, `POST /login`, `POST /logout`, `GET /me`) supporting query parameter filtering, pagination, and CORS.
- Provide a high-end SOC Analyst Dashboard with real-time polling updates, KPI cards, threat distribution donut charts, event trend line graphs, top attack type bar charts, and detailed log inspection.

---

## 3. Dataset Descriptions
The system ingests 6 core cybersecurity datasets located in `backend/data/`:
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
- **`ThreatPrediction`**: Stores M2 ML anomaly predictions, classified threat types, confidence scores, decision function anomaly scores, and explainable reason codes.

---

## 10. Security & Authentication Layer
The platform implements a server-side authentication layer powered by Flask sessions and SQLAlchemy:
- **Password Security:** Passwords are hashed using `werkzeug.security.generate_password_hash` (PBKDF2/SHA-256). No plaintext passwords exist in the database or frontend.
- **Session Management:** Secure HTTP-only cookies (`SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`).
- **Protected APIs:** `@login_required` decorator enforces server-side authentication on both M1 and M2 endpoints. Unauthenticated API requests receive `401 Unauthorized`.
- **Demo Analyst Account:** Configurable via `.env` environment variables (`SOC_ADMIN_USERNAME`, `SOC_ADMIN_PASSWORD`). Default local account: `analyst_admin` / `soc12345`.
- **Session Operations:** `POST /login` establishes session, `POST /logout` clears session, `GET /me` checks session user.

---

## Milestone 2 — AI Threat Detection & Anomaly Analysis

### 1. Feature Selection
The M2 pipeline selects key engineered security features derived from Milestone 1 telemetry to construct feature vectors for machine learning model inference (documented in `feature_selection.md`).

| Feature Name | Source | Data Type | Selected | Importance Rationale |
| :--- | :--- | :--- | :---: | :--- |
| `failed_login_attempts` | M1 Telemetry / Engineering | Integer | YES | High — Primary indicator for credential stuffing & brute-force attacks |
| `hour_of_day` | M1 Feature Engineering | Integer (0–23) | YES | Medium — Captures off-hours access anomalies |
| `is_weekend` | M1 Feature Engineering | Binary (0/1) | YES | Medium — Identifies unusual weekend activity |
| `severity_score` | M1 Standardized Schema | Float (1.0–4.0) | YES | High — Numerical weight mapping (Low=1, Medium=2, High=3, Critical=4) |
| `event_frequency` | M1 Feature Engineering | Integer | YES | High — Detects high-volume event bursts and flood attacks |
| `malicious_ip_flag` | M1 Threat Intelligence | Binary (0/1) | YES | Critical — Direct match against known malicious IOC feeds |
| `threat_feed_match` | M1 Threat Intelligence | Binary (0/1) | YES | Critical — Threat intelligence indicator match flag |
| `cvss_score` | M1 Vulnerability Feed | Float (0.0–10.0) | YES | High — Quantifies technical severity score from NIST CVE database |
| `user_alert_count` | M1 Aggregations | Integer | YES | High — Aggregate historical alert count per user entity |

---

### 2. ML Preprocessing
The ML preprocessing pipeline (`backend/ml/preprocessing.py`) uses a scikit-learn `ColumnTransformer` encapsulated in the `ThreatDataPreprocessor` class:
- **Numerical Scaling:** Missing values are imputed using median strategy (`SimpleImputer`), followed by z-score standardization using `StandardScaler` on numerical columns (`failed_login_count`, `hour_of_day`, `after_hours_flag`, `severity_score`, `event_frequency`, `alerts_per_user`, `malicious_ip_flag`, `malware_detected_encoded`, `cvss_score_final`, `impossible_travel_flag`).
- **Categorical Encoding:** Categorical attributes such as `protocol` are imputed (`most_frequent`) and transformed using `OneHotEncoder(handle_unknown='ignore', sparse_output=False)`.
- **Pipeline Artifact:** The fitted preprocessor is saved to disk as `backend/models/ml_models/preprocessing_v1.pkl` for consistent inference on new security events.

---

### 3. Anomaly Detection
The core anomaly detection engine (`backend/ml/anomaly_detection.py`) utilizes an **Isolation Forest** model:
- **Algorithm:** Scikit-learn `IsolationForest(n_estimators=200, contamination="auto", random_state=42)`.
- **Model Artifact:** Saved as `backend/models/ml_models/isolation_forest_v1.pkl`.
- **Workflow:**
  1. Extract raw telemetry feature vectors from the database or API payload.
  2. Transform feature vectors via `ThreatDataPreprocessor`.
  3. Compute raw decision function anomaly scores (`decision_function()`). Lower/negative values represent a higher degree of anomaly.
  4. Classify events into binary outputs: `Normal` (raw prediction = 1) or `Anomalous` (raw prediction = -1).

---

### 4. Threat Classification
Threat classification (`backend/ml/threat_classification.py` / `backend/ml/classifier.py`) converts anomaly predictions and security indicators into standardized threat categories:
- **Model Architecture:** An **unsupervised Isolation Forest** model coupled with a deterministic security rule engine. (Note: The engine is unsupervised because ground-truth analyst incident labels were absent during training; supervised classifiers are not claimed).
- **Classification Rules:**
  - `Brute Force`: Event type contains "brute force" OR (`failed_login_attempts >= 5` AND flagged as `Anomalous`).
  - `Malware`: `malware_detected == 'Yes'` OR event type contains "malware".
  - `SQL Injection`: Event type contains "sql injection".
  - `Phishing`: Event type contains "phishing".
  - `Privilege Escalation`: Event type contains "privilege escalation".
  - `Malicious IP Activity`: Source IP matched threat intelligence feed.
  - `Anomalous Activity`: Isolation Forest flagged event as anomalous without a specific attack pattern match.
  - `Normal Activity`: Baseline non-anomalous event.

---

### 5. Confidence & Risk Scoring
The scoring module (`backend/ml/threat_classification.py`) calculates calibrated risk and confidence scores (0.0 to 100.0) for each prediction:
- **Base Score:** Starts at `50.0` for `Anomalous` events and `10.0` for `Normal` events.
- **Additive Risk Factors:**
  - Failed logins: `+5.0` (1-4 logins), `+15.0` (5-14 logins), `+25.0` (15+ logins).
  - Malware detected: `+20.0`.
  - CVSS vulnerability score: `+ min(20.0, cvss * 2.0)`.
  - Severity level: `+ (severity_score * 4.0)`.
  - Off-hours / weekend access: `+5.0`.
  - Threat feed IP match: `+15.0`.
  - Impossible travel anomaly: `+20.0`.
- **Score Clipping:** Clamped to range `[0.0, 100.0]`.
- **Severity Rating Assignment:** Events are categorized into `Low`, `Medium`, `High`, or `Critical` threat levels based on combined risk score, M1 baseline severity, and specific threat triggers.

---

### 6. Prediction Storage
Prediction records are persisted in the SQLite `threat_predictions` database table using SQLAlchemy ORM (`backend/models/database_models.py`):

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `id` | `Integer` | Primary Key (autoincrement) |
| `event_id` | `String(50)` | Foreign key link to `security_events.event_id` (Unique, Indexed) |
| `prediction` | `String(50)` | ML Anomaly label (`Normal` or `Anomalous`) |
| `threat_type` | `String(100)` | Categorized threat type (e.g. `Brute Force`, `Malware`, `Anomalous Activity`) |
| `confidence_score` | `Float` | Calibrated risk rating (0.0 to 100.0) |
| `anomaly_score` | `Float` | Decision function output from Isolation Forest |
| `severity` | `String(50)` | Final threat severity (`Low`, `Medium`, `High`, `Critical`) |
| `model_version` | `String(50)` | Model version identifier (`isolation_forest_v1`) |
| `prediction_timestamp` | `String(50)` | ISO UTC timestamp when prediction was generated |
| `explanation` | `String(1000)` | JSON-serialized array of human-readable reason codes |

---

### 7. M2 REST APIs

| Endpoint | Method | Auth Required | Purpose | Sample Response Description |
| :--- | :--- | :---: | :--- | :--- |
| `POST /predict` | `POST` | Yes | Executes ML inference on a specific `event_id` or custom raw event payload | Returns prediction dictionary containing anomaly label, threat type, confidence score, decision score, and reason codes |
| `GET /predictions` | `GET` | Yes | Retrieves paginated and filtered prediction records | Returns `{"total": 1800, "page": 1, "limit": 25, "predictions": [...]}` filtered by `prediction`, `threat_type`, `severity`, or `search` |
| `GET /predictions/{event_id}` | `GET` | Yes | Fetches prediction record for a specific security event | Returns prediction details for the given `event_id` |
| `GET /anomalies` | `GET` | Yes | Retrieves paginated list of anomalous security events joined with event timestamps | Returns `{"total": 1207, "anomalies": [...]}` |
| `GET /model-performance` | `GET` | Yes | Retrieves unsupervised Isolation Forest performance metrics and score distributions | Returns `{"model_name": "Isolation Forest", "normal_events": 593, "anomalous_events": 1207, ...}` |
| `GET /threat-summary` | `GET` | Yes | Retrieves aggregated threat statistics, severity distributions, and confidence stats | Returns `{"total_predictions": 1800, "threat_types": {...}, "confidence": {...}}` |

---

### 8. M2 Frontend
The Milestone 2 frontend (`frontend/pages/ThreatDetection.jsx`) extends the SOC Analyst interface with dedicated AI Threat Detection capabilities:
- **AI Threat Detection Dashboard:** Interactive view rendering M2 ML insights.
- **M2 KPI Cards (`M2KPICards.jsx`):** Displays Total Predictions, Anomalous Events count & percentage, High/Critical Risk count, and Average Confidence Score.
- **Anomaly Distribution Chart (`AnomalyChart.jsx`):** Interactive SVG donut chart showing Normal vs. Anomalous event proportions.
- **Threat Trend Chart (`ThreatTrendChart.jsx`):** Time-series line chart tracking security event predictions over time.
- **Top Threat Types Chart (`ThreatTypeChart.jsx`):** Horizontal bar chart categorizing predictions by threat type.
- **Prediction Table (`ThreatTable.jsx`):** Paginated table showing Event ID, Prediction badge, Threat Type, Severity rating, Confidence score bar, Anomaly decision score, and Action trigger.
- **Confidence Information Card (`ConfidenceCard.jsx`):** Displays confidence score distribution statistics (Min, Max, Mean, Median).
- **Model Information Card (`ModelInfoCard.jsx`):** Displays active ML model details (`isolation_forest_v1`), estimator parameters (`n_estimators=200`), contamination mode, and score distribution metrics.
- **Event Investigation Modal / Details View (`EventDetailsModal.jsx` / `EventDetails.jsx`):** Deep-dive modal presenting raw event telemetry, engineered feature attributes, decision function scores, and human-readable explainable reason codes.
- **Prediction Filters & Search (`Filters.jsx`):** Interactive controls supporting multi-attribute filtering by Prediction status (`Normal`/`Anomalous`), Threat Type, Severity level, and free-text search across User, Device, and Event ID.

---

### 9. End-to-End M2 Architecture

```text
Security Event Data
↓
M1 Cleaning & Normalization
↓
M1 Enrichment & Feature Engineering
↓
M2 Feature Selection
↓
ML Preprocessing
↓
Isolation Forest Anomaly Detection
↓
Threat Classification / Analysis
↓
Confidence & Risk Scoring
↓
Prediction Storage
↓
M2 REST APIs
↓
AI Threat Detection Dashboard
```

---

### 10. M1 + M2 Combined API Summary

| Endpoint | Method | Auth Required | Layer | Description |
| :--- | :--- | :---: | :---: | :--- |
| `POST /login` | `POST` | No | Auth | Authenticate user credentials and establish session cookie |
| `POST /logout` | `POST` | Yes | Auth | Destroy active analyst session cookie |
| `GET /me` | `GET` | Yes | Auth | Retrieve current authenticated user details |
| `GET /events` | `GET` | Yes | M1 | Retrieve paginated & filtered raw/enriched security events |
| `GET /stats` | `GET` | Yes | M1 | Retrieve Milestone 1 SOC KPI metrics and counts |
| `GET /threats` | `GET` | Yes | M1 | Retrieve event type counts and threat distribution |
| `POST /predict` | `POST` | Yes | M2 | Trigger ML prediction for an event ID or custom payload |
| `GET /predictions` | `GET` | Yes | M2 | Retrieve paginated & filtered prediction records |
| `GET /predictions/{event_id}` | `GET` | Yes | M2 | Fetch prediction details for a specific event ID |
| `GET /anomalies` | `GET` | Yes | M2 | Retrieve paginated list of anomalous security events |
| `GET /model-performance` | `GET` | Yes | M2 | Retrieve Isolation Forest model metrics and score statistics |
| `GET /threat-summary` | `GET` | Yes | M2 | Retrieve threat category distribution and confidence metrics |

---

### 11. Project Structure

```text
AI-Assisted Threat Detection Dashboard/
├── .env
├── .env.example
├── .gitignore
├── Internship Milestone 1.txt
├── Milestone-2.md
├── README.md
├── feature_selection.md
├── verify_cleaning.py
├── verify_database.py
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   ├── data/
│   │   ├── assets.csv
│   │   ├── incident_history.csv
│   │   ├── mitre_attack_mapping.csv
│   │   ├── security_events.csv
│   │   ├── threat_intelligence.csv
│   │   └── vulnerabilities.csv
│   ├── database/
│   │   ├── db.py
│   │   └── soc_dashboard.db
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── anomaly_detection.py
│   │   ├── classifier.py
│   │   ├── feature_selection.py
│   │   ├── model_loader.py
│   │   ├── preprocessing.py
│   │   ├── test_anomaly_detection.py
│   │   ├── test_feature_pipeline.py
│   │   ├── test_m2_e2e_acceptance.py
│   │   ├── test_prediction_api.py
│   │   ├── test_threat_classification.py
│   │   └── threat_classification.py
│   ├── models/
│   │   ├── database_models.py
│   │   └── ml_models/
│   │       ├── isolation_forest_v1.pkl
│   │       └── preprocessing_v1.pkl
│   ├── preprocessing/
│   │   └── pipeline.py
│   ├── routes/
│   │   ├── analytics_routes.py
│   │   ├── anomaly_routes.py
│   │   ├── api.py
│   │   └── prediction_routes.py
│   ├── services/
│   │   ├── event_service.py
│   │   ├── prediction_service.py
│   │   └── scoring_service.py
│   └── utils/
│       └── helpers.py
├── frontend/
│   ├── index.html
│   ├── main.jsx
│   ├── App.jsx
│   ├── package.json
│   ├── assets/
│   ├── charts/
│   │   ├── AnomalyChart.jsx
│   │   ├── EventTrendGraph.jsx
│   │   ├── ThreatDistributionChart.jsx
│   │   ├── ThreatTrendChart.jsx
│   │   ├── ThreatTypeChart.jsx
│   │   └── TopAttackTypes.jsx
│   ├── components/
│   │   ├── AnomalyChart.jsx
│   │   ├── ConfidenceCard.jsx
│   │   ├── EventDetailsModal.jsx
│   │   ├── EventTable.jsx
│   │   ├── Filters.jsx
│   │   ├── Header.jsx
│   │   ├── KPICards.jsx
│   │   ├── M2KPICards.jsx
│   │   ├── ModelInfoCard.jsx
│   │   ├── Sidebar.jsx
│   │   └── ThreatTable.jsx
│   ├── pages/
│   │   ├── Dashboard.jsx
│   │   ├── EventDetails.jsx
│   │   ├── Login.jsx
│   │   └── ThreatDetection.jsx
│   └── services/
│       └── api.js
└── output/
    ├── cleaned_security_events.csv
    ├── enriched_security_events.csv
    ├── normalized_security_events.csv
    ├── processing_summary.json
    ├── security_events_enriched.csv
    ├── security_events_mitre.csv
    └── security_events_normalized.csv
```

---

### 12. Installation and Running

#### System Requirements
- Python 3.10+ installed.
- Node.js 18+ (optional, only if rebuilding frontend assets; pre-bundled single-page app is served by Flask).

#### 1. Python Dependencies Installation
From the project root directory, install all backend and machine learning dependencies:
```bash
pip install -r backend/requirements.txt
```

#### 2. Model & Preprocessor Artifact Verification
Ensure model artifacts exist under `backend/models/ml_models/`:
- `isolation_forest_v1.pkl`
- `preprocessing_v1.pkl`

*(If missing, running `python backend/ml/anomaly_detection.py` trains the Isolation Forest pipeline and generates both model artifacts).*

#### 3. Database & Application Startup
Run the unified Flask application:
```bash
python backend/app.py
```
This command automatically:
- Initializes the SQLite database (`backend/database/soc_dashboard.db`).
- Seeds database tables from `backend/preprocessing/pipeline.py` if needed.
- Computes ML predictions and populates the `threat_predictions` database table.
- Starts the web server at `http://127.0.0.1:5000/`.

#### 4. Accessing the Platform
Open your browser and navigate to:
```text
http://127.0.0.1:5000/
```
- **Login Credentials:** Username: `analyst_admin` | Password: `soc12345`

---

### 13. Milestone 1 + Milestone 2 Completion Checklist

#### Milestone 1
- [x] Data Collection
- [x] Data Cleaning
- [x] Normalization
- [x] Severity Standardization
- [x] Threat Enrichment
- [x] MITRE Mapping
- [x] Feature Engineering
- [x] Database Storage
- [x] REST APIs (`GET /events`, `GET /stats`, `GET /threats`)
- [x] Analyst Dashboard
- [x] SVG Charts (Distribution, Line Graph, Bar Chart)
- [x] Interactive Filters
- [x] Authentication & Session Management

#### Milestone 2
- [x] Feature Selection (`feature_selection.md`)
- [x] ML Preprocessing (`ThreatDataPreprocessor`, StandardScaler, OneHotEncoder)
- [x] Isolation Forest Anomaly Detection (`isolation_forest_v1.pkl`)
- [x] Threat Classification (Rule-assisted threat category mapping)
- [x] Confidence / Risk Scoring (0.0 to 100.0 score calibration)
- [x] Prediction Storage (`threat_predictions` database table)
- [x] M2 REST APIs (`POST /predict`, `GET /predictions`, `GET /anomalies`, `GET /model-performance`, `GET /threat-summary`)
- [x] AI Dashboard View (`ThreatDetection.jsx`)
- [x] Prediction Table (`ThreatTable.jsx`)
- [x] Interactive M2 Charts (Anomaly Distribution, Threat Trends, Threat Types)
- [x] Event Investigation Modal (`EventDetailsModal.jsx`)
- [x] Prediction Filters & Search

---

### 14. Results & Verification

Verified metrics extracted from the current system database execution:

#### Milestone 1 Metrics
- **Total Security Events Processed:** 1,800
- **Severity Breakdown:**
  - Critical: 346
  - High: 573
  - Medium: 437
  - Low: 444
- **Vulnerability Events (CVSS > 0):** 1,373
- **Threat Feed IP Matches:** 0 *(Unmatched IPs cleanly preserved as `No Match`)*
- **MITRE ATT&CK Mapped Events:** 179
- **MITRE Mapping Coverage:** 9.94%
- **Total SOC Incidents Tracked:** 1 *(Active: 0, Closed: 1)*
- **Malware-Related Events:** 165

#### Milestone 2 Metrics
- **Total Prediction Records:** 1,800
- **Anomalous Events Flagged:** 1,207 (67.06%)
- **Normal Events Flagged:** 593 (32.94%)
- **Isolation Forest Decision Scores:**
  - Minimum Anomaly Score: -0.2184
  - Maximum Anomaly Score: 0.1741
  - Mean Anomaly Score: -0.0526
  - Median Anomaly Score: -0.0632
- **Confidence Scores:** Range: 14.0 to 100.0 (Mean: ~73.6)

---

### 15. Known Limitations

#### Milestone 1 Limitations
1. **Threat Intelligence Feed Coverage:** The reference `threat_intelligence.csv` file contains 1 reference IOC indicator. Unmatched IP addresses are preserved cleanly as `No Match` without injecting false threat data.
2. **MITRE ATT&CK Technique Coverage:** MITRE mapping relies on exact event type mapping rules from `mitre_attack_mapping.csv` (179 events mapped, 9.94% coverage). Unmapped events default to `Unknown`.

#### Milestone 2 Limitations
1. **Unsupervised Anomaly Model Baseline:** Isolation Forest operates as an unsupervised algorithm on unlabelled telemetry data. Precise supervised classification metrics (Precision, Recall, F1-Score) require ground-truth analyst incident labels.
2. **Deterministic Threat Classifier Logic:** Threat category mapping combines Isolation Forest anomaly predictions with rule-based heuristics. While highly effective, complex multi-stage APT attacks may require fine-tuned supervised classifiers as analyst labels accumulate.
