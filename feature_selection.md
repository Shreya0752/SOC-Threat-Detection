This document defines the explicit feature selection matrix used by the AI-Based Threat Detection and Anomaly Engine derived from the normalized and enriched dataset in Milestone 1.

##  Selected Feature Matrix Overview

| Feature Name | Source | Data Type | Selected | Importance Rationale |

| `failed_login_attempts` | M1 Preprocessing | Integer | YES | High (Critical indicator for Brute Force & Password Spraying attacks) |
| `hour_of_day` | M1 Feature Engineering | Integer (0–23) | YES | Medium (Detects off-hours & anomalous login schedules) |
| `is_weekend` | M1 Feature Engineering | Binary (0 or 1) | YES | Medium (Detects unusual weekend access patterns) |
| `severity_score` | M1 Standardized Schema | Float (1.0–4.0) | YES | High (Maps Low=1, Medium=2, High=3, Critical=4 for risk weighting) |
| `event_frequency` | M1 Feature Engineering | Integer | YES | High (Identifies flood attacks, port scans, & high-volume events) |
| `malicious_ip_flag` | M1 Threat Enrichment | Binary (0 or 1) | YES | Critical (Matches against known threat intelligence IOC feeds) |
| `threat_feed_match` | M1 Threat Enrichment | Binary (0 or 1) | YES | Critical (Direct threat intelligence feed indicator match) |
| `cvss_score` | M1 Vulnerability Data | Float (0.0–10.0) | YES | High (Quantifies CVE vulnerability impact score) |
| `user_alert_count` | M1 Feature Engineering | Integer | YES | High (Aggregates historical alert count per user entity) |


## Feature Rationale & Data Pipeline

1. `failed_login_attempts`
   - Type: Numeric (Integer)
   - Importance: 0.22
   - Why Selected:Repeated failed login attempts are the primary signature for credential stuffing and brute-force intrusion attempts.

2. `malicious_ip_flag` & `threat_feed_match`
   - Type:Binary Flags (0 / 1)
   - Importance:0.25
   - Why Selected:Directly enriches security events with verified external Indicator of Compromise (IOC) feeds compiled in Milestone 1.

3. `cvss_score`
   - Type:Numeric (Float)
   - Importance: 0.18
   - Why Selected: Evaluates technical vulnerability exploitation risk based on NIST Common Vulnerability Scoring System.

4. `hour_of_day` & `is_weekend`
   - Type:Temporal Numerical (Integer)
   - Importance:0.15
   - Why Selected:Captures user behavior temporal baseline to flag suspicious after-hours and weekend network activity.

5. `event_frequency` & `user_alert_count`**
   -Type:Entity Aggregations (Integer)
   -Importance:0.20
   -Why Selected:Detects volume anomalies and high-frequency behavioral spikes per IP address and user account.


## Model Compatibility & Input Vector Format

The preprocessed feature vector format passed into **Isolation Forest** (`isolation_forest_v1.pkl`) is:
```python
[
    failed_login_attempts,
    hour_of_day,
    is_weekend,
    severity_score,
    event_frequency,
    malicious_ip_flag,
    threat_feed_match,
    cvss_score,
    user_alert_count
]
```
- Algorithm:Isolation Forest (`n_estimators=100`, `contamination=0.15`)
- Scaling: `StandardScaler` fitted on numeric features (`failed_login_attempts`, `event_frequency`, `user_alert_count`, `cvss_score`).
