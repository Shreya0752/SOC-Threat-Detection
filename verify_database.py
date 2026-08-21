import sqlite3

DB_PATH = "backend/database/soc_dashboard.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

print("=" * 70)
print("SOC THREATDETECT AI - DATABASE VERIFICATION")
print("=" * 70)


# ============================================================
# 1. DATABASE CONNECTION
# ============================================================

print("\n1. DATABASE CONNECTION")
print("-" * 70)

print("Database connected successfully.")
print("Database:", DB_PATH)


# ============================================================
# 2. DATABASE TABLES
# ============================================================

print("\n2. DATABASE TABLES")
print("-" * 70)

cursor.execute("""
    SELECT name
    FROM sqlite_master
    WHERE type='table'
    ORDER BY name
""")

tables = cursor.fetchall()

for table in tables:
    print("-", table[0])


# ============================================================
# 3. SECURITY EVENTS
# ============================================================

print("\n3. SECURITY EVENTS")
print("-" * 70)

cursor.execute("SELECT COUNT(*) FROM security_events")

total_events = cursor.fetchone()[0]

print("Total security events:", total_events)


# ============================================================
# 4. SECURITY EVENT SCHEMA
# ============================================================

print("\n4. SECURITY EVENT SCHEMA")
print("-" * 70)

cursor.execute("PRAGMA table_info(security_events)")

columns_info = cursor.fetchall()

columns = [row[1] for row in columns_info]

for column in columns:
    print("-", column)


# ============================================================
# 5. MITRE ATT&CK DATA INTEGRITY
# ============================================================

print("\n5. MITRE ATT&CK DATA INTEGRITY")
print("-" * 70)

if "mitre_mapped" in columns:

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE mitre_mapped = 1
    """)

    mapped_count = cursor.fetchone()[0]

    print("mitre_mapped = 1:", mapped_count)

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE mitre_mapped = 1
        AND mitre_id IS NOT NULL
        AND TRIM(mitre_id) != ''
        AND LOWER(TRIM(mitre_id)) != 'unknown'
    """)

    valid_mitre_count = cursor.fetchone()[0]

    print("Mapped events with actual MITRE ID:", valid_mitre_count)

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE mitre_mapped = 1
        AND (
            mitre_id IS NULL
            OR TRIM(mitre_id) = ''
            OR LOWER(TRIM(mitre_id)) = 'unknown'
        )
    """)

    unknown_mitre_count = cursor.fetchone()[0]

    print("Mapped events with Unknown MITRE ID:", unknown_mitre_count)

    if valid_mitre_count > 0:

        cursor.execute("""
            SELECT event_type, mitre_id, technique_name, tactic
            FROM security_events
            WHERE mitre_mapped = 1
            AND mitre_id IS NOT NULL
            AND TRIM(mitre_id) != ''
            AND LOWER(TRIM(mitre_id)) != 'unknown'
            LIMIT 10
        """)

        print("\nActual MITRE mappings:")

        for row in cursor.fetchall():
            print(row)

else:

    print("mitre_mapped column not found.")


# ============================================================
# 6. ENGINEERED FEATURES
# ============================================================

print("\n6. ENGINEERED FEATURES")
print("-" * 70)

features = [
    "failed_login_count",
    "hour_of_day",
    "weekend_flag",
    "severity_score",
    "event_frequency",
    "malicious_ip_flag",
    "threat_feed_match",
    "cvss_score_final",
    "alerts_per_user"
]

for feature in features:

    if feature in columns:
        print(f"- {feature}: YES")
    else:
        print(f"- {feature}: NO")


# ============================================================
# 7. THREAT INTELLIGENCE
# ============================================================

print("\n7. THREAT INTELLIGENCE")
print("-" * 70)

if "threat_feed_match" in columns:

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_events
        WHERE threat_feed_match = 1
    """)

    threat_matches = cursor.fetchone()[0]

    print("Raw threat-feed matches:", threat_matches)

else:

    print("threat_feed_match column not found.")


# ============================================================
# 8. INCIDENT DATA
# ============================================================

print("\n8. INCIDENT DATA")
print("-" * 70)

# Check whether incident_history table exists

cursor.execute("""
    SELECT name
    FROM sqlite_master
    WHERE type='table'
    AND name='incident_history'
""")

incident_table = cursor.fetchone()

if incident_table:

    cursor.execute("SELECT COUNT(*) FROM incident_history")

    print(
        "Incident history table records:",
        cursor.fetchone()[0]
    )

else:

    print("incident_history table not found.")

    # Check incident columns inside security_events

    if "incident_id" in columns:

        cursor.execute("""
            SELECT COUNT(*)
            FROM security_events
            WHERE incident_id IS NOT NULL
            AND TRIM(incident_id) != ''
            AND LOWER(TRIM(incident_id))
                NOT IN ('none', 'nan', 'null')
        """)

        linked_events = cursor.fetchone()[0]

        print(
            "Security events linked to incidents:",
            linked_events
        )

        cursor.execute("""
            SELECT DISTINCT
                incident_id,
                incident_type,
                assigned_to,
                incident_status
            FROM security_events
            WHERE incident_id IS NOT NULL
            AND TRIM(incident_id) != ''
            AND LOWER(TRIM(incident_id))
                NOT IN ('none', 'nan', 'null')
        """)

        incident_rows = cursor.fetchall()

        print("\nIncident records represented in security_events:")

        for row in incident_rows:
            print(row)


# ============================================================
# 9. CLEANING STATISTICS
# ============================================================

print("\n9. CLEANING STATISTICS")
print("-" * 70)

cursor.execute("""
    SELECT name
    FROM sqlite_master
    WHERE type='table'
    AND name='cleaning_stats'
""")

cleaning_table = cursor.fetchone()

if cleaning_table:

    cursor.execute("SELECT * FROM cleaning_stats")

    cleaning_rows = cursor.fetchall()

    print("Cleaning statistics:")

    for row in cleaning_rows:
        print(row)

else:

    print("cleaning_stats table not found.")


# ============================================================
# 10. SAMPLE SECURITY EVENTS
# ============================================================

print("\n10. SAMPLE SECURITY EVENTS")
print("-" * 70)

sample_columns = []

for column in [
    "event_id",
    "event_type",
    "severity",
    "source_ip"
]:

    if column in columns:
        sample_columns.append(column)

if sample_columns:

    query = f"""
        SELECT {", ".join(sample_columns)}
        FROM security_events
        LIMIT 5
    """

    cursor.execute(query)

    for row in cursor.fetchall():
        print(row)

else:

    print("Expected event columns not found.")


# ============================================================
# 11. FINAL SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("DATABASE VERIFICATION SUMMARY")
print("=" * 70)

print("Database connection: PASS")

if total_events > 0:
    print("Security events table: PASS")
else:
    print("Security events table: FAIL")

print("Total events:", total_events)

if "mitre_mapped" in columns:
    print("MITRE mapping field: PRESENT")
else:
    print("MITRE mapping field: NOT FOUND")

if "risk_label" in columns:
    cursor.execute("SELECT risk_label, COUNT(*) FROM security_events GROUP BY risk_label")
    risk_counts = cursor.fetchall()
    print("Risk labels stored: PRESENT ->", risk_counts)
else:
    print("Risk labels stored: NOT FOUND")

print("\nEngineered features:")

for feature in features:

    status = "YES" if feature in columns else "NO"

    print(f"{feature}: {status}")

print("\nVerification complete.")

# IMPORTANT:
# Close the database ONLY after ALL queries are finished.

conn.close()