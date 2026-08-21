Milestone 2 — AI-Based Threat Detection \& anomaly Analysis Engine.





* **Objective :**

Develop an AI/ML-based threat detection engine capable of identifying abnormal cybersecurity activities, suspicious behavior patterns, and attack indicators, and generate automated threat classifications and confidence scores.





* In Milestone 1 , You have prepared



Raw Security Data

&#x20;       ↓

Cleaning

&#x20;       ↓

Normalization

&#x20;       ↓

Feature Engineering

&#x20;       ↓

MongoDB

&#x20;       ↓

REST APIs

&#x20;       ↓

Frontend







* For Milestone 2 adds the AI layer:



Security Events

&#x20;      ↓

Processed Features

&#x20;      ↓

ML Detection Engine

&#x20;      ↓

Anomaly Detection

&#x20;      ↓

Threat Classification

&#x20;      ↓

Confidence Score

&#x20;      ↓

Threat Result

&#x20;      ↓

MongoDB

&#x20;      ↓

FastAPI

&#x20;      ↓

React Dashboard







* Difference In M-1 \& M-2 :



Milestone 1 = "What happened?"



Milestone 2 = "Is this activity suspicious, and how suspicious is it?"







* What should NOT be done yet?



\~Don't start with Deep Learning



You don't need CNNs, LSTMs, Transformers, etc.



\~ Don't use an LLM just because the project is called AI-assisted



LLM is not mandatory for the core threat detection model.



\~Don't build risk prioritization yet



That belongs primarily to Milestone 3.



\~ Don't redesign the database



Extend the existing schema where necessary.



\~ Don't throw away Milestone 1



Milestone 2 must use the processed data produced in Milestone 1.







* Recommended ML approach :--



For this project, I recommend using two layers.



Layer 1 — Anomaly Detection

Layer 2 — Threat Classification









* Layer 1 — Anomaly Detection



Use:



Isolation Forest  Recommended



It works well for identifying unusual observations when you don't have reliable labels for every security event.



Other acceptable algorithms:



Local Outlier Factor

One-Class SVM

DBSCAN



But Isolation Forest should be the primary recommended approach.







* Layer 2 — Threat Classification



If the dataset contains reliable labels, you can train a supervised classifier such as:



Random Forest

XGBoost

Logistic Regression

SVM









* What features should you use :



\~Authentication:

failed\_login\_attempts

login\_frequency

login\_hour



\~Network :

connection\_frequency

unique\_destination\_count

protocol



\~User behavior :

events\_per\_user

unique\_ip\_count

after\_hours\_activity



\~Vulnerability :

cvss\_score

vulnerability\_count



\~Security :

severity\_score

malware\_detected

event\_frequency



\~Location

source\_country

destination\_country

impossible\_travel\_flag









* Important Feature: Impossible Travel



This will make the project look much more intelligent.



Example:

User: Rahul



10:00 AM → India



10:15 AM → USA



Obviously, the user cannot realistically travel between these locations within 15 minutes.



This becomes a suspicious behavior indicator.



so,

impossible\_travel\_flag = 1









* Create an ML Feature Matrix:



The backend team should create something like:



| event\_id | failed\_logins | login\_frequency | cvss | malware | after\_hours | impossible\_travel | event\_frequency |





| EVT001   |             2 |               5 |  2.1 |       0 |           0 |                 0 |               8 |

| EVT002   |            18 |              24 |  8.9 |       0 |           1 |                 1 |              31 |

| EVT003   |             1 |               3 |  1.2 |       0 |           0 |                 0 |               4 |











* Data preprocessing for ML :



Before training:



Handle missing values:

NaN → appropriate value



Encode categorical variables



For example:

protocol

event\_type

OS

department



can be encoded using:



One-Hot Encoding

Label Encoding where appropriate



Scale Feature:



For algorithms that benefit from scaling, use:

StandardScaler



NOTE:-Do not blindly scale everything. The preprocessing should match the selected algorithm.











* Train the Anomaly Detection Model :



Example flow:

Processed Dataset

&#x20;      ↓

Feature Selection

&#x20;      ↓

Preprocessing

&#x20;      ↓

Isolation Forest

&#x20;      ↓

Anomaly Score

&#x20;      ↓

Normal / Anomalous



The model can generate: -->

1 → Normal



\-1 → Anomaly



You should convert that into a more understandable field:



Normal

Suspicious









* Generate Threat Confidence Score :-->



This is an important Milestone 2 requirement.

For Example-->



Anomaly Score

&#x20;      +

Severity

&#x20;      +

Failed Login Behavior

&#x20;      +

Malware Indicator

&#x20;      +

Impossible Travel

&#x20;      ↓

Confidence Score



Example Output:



| Event  | Prediction | Confidence |

| ------ | ---------- | ---------: |

| EVT001 | Normal     |        12% |

| EVT002 | Suspicious |        91% |

| EVT003 | Suspicious |        84% |



Note : Do not claim that the confidence score is the actual probability of an attack unless the model is calibrated to produce probabilities.









* Threat Classification :



The output should be understandable to a SOC analyst.



For Example:



Normal

Low Threat

Medium Threat

High Threat

Critical Threat



Or



Normal

Suspicious

Malicious



You should choose one consistent scheme and document it.









* Recommended Detection Rules :-

This makes the system more realistic.



Example:



Brute Force:

failed\_login\_attempts > 10



→ suspicious



Malware:

malware\_detected = Yes



→ high suspicion



Critical CVE:

cvss\_score >= 9



→ high-risk indicator



Impossible Travel:

impossible\_travel\_flag = 1



→ suspicious



Multiple suspicious indicators

Brute Force

\+

Critical CVE

\+

After-hours activity



→ highly suspicious



This is called a hybrid detection approach:



ML Detection

&#x20;     +

Security Rules

&#x20;     ↓

Threat Detection Engine



Note: This is actually a very good enhancement for your project.









* Backend Team — Milestone 2 Tasks :



Task 1 — Feature Selection



Identify which Milestone 1 features should be used by the ML model.



Deliverable:



feature\_selection.md



Explain:



Feature

Why selected

Data type

Importance









* Task 2 — ML Preprocessing :



Create:



ml\_preprocessing.py



Perform:



Missing value handling

Encoding

Scaling where required

Feature selection









* Task 3 — Train Model :

Create:



anomaly\_detection.py



Train:



Isolation Forest



and optionally compare it with:



LOF

One-Class SVM







* Evaluate the Model :

If You have labelled data, calculate:



Accuracy

Precision

Recall

F1-score

Confusion Matrix



If reliable labels exist:



Focus particularly on Precision, Recall and F1-score, not accuracy alone.









* For cybersecurity detection, missing a genuinely malicious event can be costly, so recall is especially important, while precision helps control false alarms.









* Model Comparison :

This would make  milestone stronger.



Example



| Model               | Precision | Recall |   F1 |

| ------------------- | --------: | -----: |



| Isolation Forest    |      0.87 |   0.91 | 0.89 |

| Random Forest       |      0.90 |   0.94 | 0.92 |

| Logistic Regression |      0.82 |   0.88 | 0.85 |











* Store Predictions in MongoDB :

This is where your Milestone 1 database becomes useful.



Create a collection such as:



threat\_predictions



Example:



{

&#x20; "event\_id": "EVT00231",

&#x20; "prediction": "Suspicious",

&#x20; "threat\_type": "Brute Force",

&#x20; "confidence\_score": 91,

&#x20; "anomaly\_score": -0.72,

&#x20; "severity": "High",

&#x20; "model\_version": "IF\_v1",

&#x20; "prediction\_timestamp": "2026-08-07T10:30:00"

}



Why store predictions?



Because later you can use them for:-



Threat history

Analytics

Feedback

Model monitoring

Retraining

Milestone 3 risk scoring













* Backend APIs :-->



POST /predict

Send a security event and receive its prediction.



Example:



{

&#x20; "event\_type": "Brute Force",

&#x20; "failed\_login\_attempts": 18,

&#x20; "cvss\_score": 8.9

}



Response:



{

&#x20; "prediction": "Suspicious",

&#x20; "confidence\_score": 91,

&#x20; "severity": "High"

}











* GET /predictions



GET /predictions/{event\_id}



GET /anomalies



GET /model-performance



GET /threat-summary









* API's For M-2:-->



POST /predict



GET /predictions



GET /predictions/{event\_id}



GET /anomalies



GET /model-performance



GET /threat-summary









* Frontend Team — Milestone 2 :-->



The frontend should now evolve from a simple monitoring dashboard into an AI Threat Detection Dashboard.



Add:

AI Detection Overview



Cards:



Total Events

Anomalies Detected

Normal Events

High-Risk Events

Critical Threats









* Threat Detection Table



Columns:



Event ID

Event Type

Prediction

Confidence	Severity

Timestamp









* Anomaly Distribution



Pie/Donut chart:



Normal

Suspicious

Critical







* Threat Trend :-->



Line chart:



Time

&#x20;  ↓

Number of detected anomalies









* Threat Type Chart :-->



Bar chart:



Brute Force

Malware

Phishing

SQL Injection

Privilege Escalation











* Event Investigation Page :--?



{This would be a great feature.}



When the analyst clicks:



EVT00231



show:

Event Details



Source IP

Destination IP

User

Event Type

Timestamp

Asset

Severity

CVSS



Then:



AI Analysis

Prediction: Suspicious



Confidence: 91%



Reason:

• 18 failed login attempts

• After-hours activity

• Multiple login attempts

• Known suspicious IP



NOTE :- This will make the project feel much more like a real SOC tool.











* Explainable AI — Highly Recommended



Don't just show:



"Threat Detected"



Show:



Why was it detected?



For example:



Threat detected because:



✓ Failed login attempts > threshold

✓ Unusual login time

✓ Impossible travel detected

✓ High event frequency



This can be implemented using feature contribution/rule explanations without requiring a complicated LLM.



This is one of the features I'd strongly recommend.















* API Integration :--



Final Flow;



React

&#x20; ↓

Axios

&#x20; ↓

FastAPI

&#x20; ↓

ML Model

&#x20; ↓

MongoDB

&#x20; ↓

Prediction

&#x20; ↓

React Dashboard















* Milestone 2 Folder Structure :



BACKEND:-->



backend/

│

├── app.py

│

├── routes/

│   ├── prediction\_routes.py

│   ├── anomaly\_routes.py

│   └── analytics\_routes.py

│

├── ml/

│   ├── anomaly\_detection.py

│   ├── classifier.py

│   ├── preprocessing.py

│   └── model\_loader.py

│

├── models/

│   └── model.pkl

│

├── services/

│   ├── prediction\_service.py

│   └── scoring\_service.py

│

├── database/

│

└── utils/









FRONTEND:-->



frontend/

│

├── src/

│

├── pages/

│   ├── Dashboard.jsx

│   ├── ThreatDetection.jsx

│   └── EventDetails.jsx

│

├── components/

│   ├── ThreatTable.jsx

│   ├── ConfidenceCard.jsx

│   └── AnomalyChart.jsx

│

├── services/

│   └── api.js

│

└── charts/









Day 	Backend				Frontend



1	Feature selection		Understand new ML outputs

2	ML preprocessing		Design detection UI

3	Train anomaly model		Threat table

4	Model evaluation		Charts

5	Threat classification		Event details

6	Confidence scoring		AI analysis section

7	MongoDB prediction storage	API integration

8	Prediction APIs			Dashboard integration

9	Testing \& optimization		Testing \& UI polishing

10	Documentation + Demo		Documentation + Demo







Milestone 2 Deliverables:



\*Backend\*



&#x20;Feature selection

&#x20;ML preprocessing pipeline

&#x20;Anomaly detection model

&#x20;Threat classification model/rules

&#x20;Threat confidence score

&#x20;Model evaluation

&#x20;Prediction storage in MongoDB

&#x20;Prediction APIs

&#x20;API testing

&#x20;Model saved/versioned



\*Frontend\*



&#x20;AI Threat Detection dashboard

&#x20;Threat prediction table

&#x20;Confidence score visualization

&#x20;Anomaly charts

&#x20;Threat-type charts

&#x20;Event investigation page

&#x20;API integration

&#x20;Filters/search

&#x20;Responsive UI











In Milestone 1, we prepared and stored the cybersecurity data.



In Milestone 2, we will use that data to detect suspicious/anomalous security events using ML.



{Just keep this in mind}





Our target architecture is:-->



MongoDB

&#x20;  ↓

Processed Security Events

&#x20;  ↓

ML Preprocessing

&#x20;  ↓

Feature Selection

&#x20;  ↓

Anomaly Detection

&#x20;  ↓

Threat Classification

&#x20;  ↓

Confidence Score

&#x20;  ↓

MongoDB

&#x20;  ↓

FastAPI

&#x20;  ↓

React Dashboard Ready







Backend Team-->



Your main responsibility:



Data

&#x20;↓

Features

&#x20;↓

ML Model

&#x20;↓

Prediction

&#x20;↓

MongoDB

&#x20;↓

API





Frontend Team-->



Your responsibility:



API

&#x20;↓

React

&#x20;↓

Threat Dashboard

&#x20;↓

Charts

&#x20;↓

Investigation UI













Initial pipeline-->



Security Events

&#x20;     ↓

Select Features

&#x20;     ↓

Preprocess

&#x20;     ↓

Isolation Forest

&#x20;     ↓

Anomaly Score

&#x20;     ↓

Normal / Anomalous



Note: Don't start with five algorithms.first make one model work correctly. after that, you can compare another model if time permits.







Optional Features After Core Work:



1\. Explainable AI



Show why an event was flagged.



2\. Real-time prediction



Allow an analyst to enter/upload an event and get an instant prediction.



3\. Model comparison



Compare Isolation Forest vs another suitable model.



4\. Threshold tuning



Allow the detection threshold to be adjusted and observe changes in alerts.



5\. Prediction history



Show previously detected anomalies.



6\. False-positive marking



Allow analysts to mark:

True Positive

False Positive







Day 1-->



Backend:



✔ Load Milestone 1 data

✔ Select ML features

✔ Create preprocessing pipeline

✔ Create test dataset



Frontend:



✔ Create Threat Detection page

✔ Create Threat Table

✔ Create KPI cards





Day 2-->



Backend:



✔ Train Isolation Forest

✔ Generate anomaly predictions

✔ Generate anomaly scores



Frontend:



✔ Create threat charts

✔ Create confidence visualization



Day 3-->



Backend:



✔ Threat classification

✔ Confidence calculation

✔ Save predictions to MongoDB



Frontend:



✔ Connect first API

✔ Display real prediction data



So after these three days,you guys have their first working AI prediction visible in React.



Backbone of M-2



INPUT → ML → PREDICTION → DATABASE → API → DASHBOARD









But just take help from the basic flow:



Security Event → Feature Selection → Preprocessing → Isolation Forest → Anomaly Prediction → Confidence/Severity → MongoDB → FastAPI → React Dashboard

