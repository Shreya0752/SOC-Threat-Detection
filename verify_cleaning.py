import pandas as pd
import sqlite3

CSV_PATH = "backend/data/security_events.csv"
DB_PATH = "backend/database/soc_dashboard.db"

print("=" * 75)
print("         DATA CLEANING VERIFICATION")
print("=" * 75)



print("\n" + "=" * 75)
print("1. BEFORE CLEANING - ORIGINAL DATASET")
print("=" * 75)

security = pd.read_csv(CSV_PATH)

print("Rows before cleaning:", len(security))
print("Columns before cleaning:", len(security.columns))


print("\n    Missing Values BEFORE Cleaning ")
missing_before = security.isnull().sum()
print(missing_before)
total_missing_before = missing_before.sum()
print("\nTotal missing cells before cleaning:",
      total_missing_before)



duplicates_before = security.duplicated().sum()
print("\n    Duplicate Check BEFORE Cleaning ")
print("Duplicate rows:", duplicates_before)




print("\n    Timestamp Check BEFORE Cleaning ")

if "timestamp" in security.columns:

    timestamp_before = pd.to_datetime(
        security["timestamp"],
        errors="coerce"
    )

    invalid_timestamps_before = timestamp_before.isnull().sum()

    print(
        "Invalid timestamps:",
        invalid_timestamps_before
    )

else:

    invalid_timestamps_before = None

    print("timestamp column not found")



print("\n    Severity Check BEFORE Cleaning ")
if "severity" in security.columns:

    severity_before = (
        security["severity"]
        .dropna()
        .astype(str)
        .str.strip()
    )

    print("Unique severity values:")

    print(
        sorted(
            severity_before.unique()
        )
    )

    allowed_severity = {
        "Critical",
        "High",
        "Medium",
        "Low"
    }

    unknown_severity_before = (
        ~severity_before.str.title().isin(
            allowed_severity
        )
    ).sum()

    print(
        "Unknown/inconsistent severity values:",
        unknown_severity_before
    )

else:

    unknown_severity_before = None

    print("severity column not found")




print("\n    Blank String Check BEFORE Cleaning ")

blank_cells_before = 0

for column in security.columns:

    blank_cells_before += (
        security[column]
        .astype(str)
        .str.strip()
        .eq("")
        .sum()
    )

print(
    "Blank string cells:",
    blank_cells_before
)



print("\n    Standard Security Event Schema ")

required_columns = [
    "event_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "event_type",
    "severity",
    "status"
]

for column in required_columns:

    if column in security.columns:
        print(f"{column}: PRESENT")
    else:
        print(f"{column}: MISSING")




print("\n    Data Types BEFORE Cleaning ")

print(security.dtypes)




print("\n" + "=" * 75)
print("2. AFTER CLEANING - PROCESSED DATABASE")
print("=" * 75)

conn = sqlite3.connect(DB_PATH)

cursor = conn.cursor()



processed = pd.read_sql_query(
    "SELECT * FROM security_events",
    conn
)

print("Rows after cleaning:",
      len(processed))

print("Columns after processing:",
      len(processed.columns))




print("\n    Missing Values AFTER Cleaning ")

missing_after = processed.isnull().sum()

print(missing_after)

total_missing_after = missing_after.sum()

print(
    "\nTotal missing cells after processing:",
    total_missing_after
)


duplicates_after = processed.duplicated().sum()

print("\n    Duplicate Check AFTER Cleaning ")

print(
    "Duplicate rows:",
    duplicates_after
)




print("\n    Timestamp Check AFTER Cleaning ")

if "timestamp" in processed.columns:

    timestamp_after = pd.to_datetime(
        processed["timestamp"],
        errors="coerce"
    )

    invalid_timestamps_after = (
        timestamp_after.isnull().sum()
    )

    print(
        "Invalid timestamps:",
        invalid_timestamps_after
    )

else:

    invalid_timestamps_after = None

    print("timestamp column not found")


# ============================================================
# 14. SEVERITY CHECK AFTER CLEANING
# ============================================================

print("\n--- Severity Check AFTER Cleaning ---")

if "severity" in processed.columns:

    severity_after = (
        processed["severity"]
        .dropna()
        .astype(str)
        .str.strip()
    )

    print("Unique severity values:")

    print(
        sorted(
            severity_after.unique()
        )
    )

    allowed_severity = {
        "Critical",
        "High",
        "Medium",
        "Low"
    }

    invalid_severity_after = (
        ~severity_after.isin(
            allowed_severity
        )
    ).sum()

    print(
        "Invalid/unknown severity values:",
        invalid_severity_after
    )

else:

    invalid_severity_after = None

    print("severity column not found")


# ============================================================
# 15. EVENT ID CHECK AFTER CLEANING
# ============================================================

print("\n--- Event ID Check AFTER Cleaning ---")

if "event_id" in processed.columns:

    null_event_ids = processed["event_id"].isnull().sum()

    duplicate_event_ids = (
        processed["event_id"].duplicated().sum()
    )

    print(
        "Null event IDs:",
        null_event_ids
    )

    print(
        "Duplicate event IDs:",
        duplicate_event_ids
    )

else:

    null_event_ids = None
    duplicate_event_ids = None

    print("event_id column not found")


# ============================================================
# 16. TEXT STANDARDIZATION CHECK
# ============================================================

print("\n--- Text Standardization AFTER Cleaning ---")

text_columns = [
    "event_type",
    "protocol",
    "severity",
    "status",
    "department",
    "malware_detected"
]

for column in text_columns:

    if column in processed.columns:

        values = (
            processed[column]
            .dropna()
            .astype(str)
        )

        whitespace_values = (
            values != values.str.strip()
        ).sum()

        print(
            f"{column}: "
            f"{whitespace_values} values "
            f"with leading/trailing spaces"
        )


# ============================================================
# 17. CLEANING STATISTICS STORED BY APPLICATION
# ============================================================

print("\n" + "=" * 75)
print("3. APPLICATION RECORDED CLEANING STATISTICS")
print("=" * 75)

cursor.execute(
    "SELECT * FROM cleaning_stats"
)

cleaning_rows = cursor.fetchall()

for row in cleaning_rows:
    print(row)


# ============================================================
# 18. BEFORE VS AFTER REPORT
# ============================================================

print("\n" + "=" * 75)
print("4. BEFORE vs AFTER CLEANING REPORT")
print("=" * 75)

print(
    f"{'Metric':<35}"
    f"{'Before':<15}"
    f"{'After':<15}"
)

print("-" * 65)

print(
    f"{'Rows':<35}"
    f"{len(security):<15}"
    f"{len(processed):<15}"
)

print(
    f"{'Duplicate rows':<35}"
    f"{duplicates_before:<15}"
    f"{duplicates_after:<15}"
)

print(
    f"{'Missing cells':<35}"
    f"{total_missing_before:<15}"
    f"{total_missing_after:<15}"
)

print(
    f"{'Invalid timestamps':<35}"
    f"{invalid_timestamps_before:<15}"
    f"{invalid_timestamps_after:<15}"
)

print(
    f"{'Blank string cells':<35}"
    f"{blank_cells_before:<15}"
    f"{'-':<15}"
)

print(
    f"{'Invalid severity values':<35}"
    f"{unknown_severity_before:<15}"
    f"{invalid_severity_after:<15}"
)

print(
    f"{'Duplicate event IDs':<35}"
    f"{'-':<15}"
    f"{duplicate_event_ids:<15}"
)


# ============================================================
# 19. FINAL VERIFICATION
# ============================================================

print("\n" + "=" * 75)
print("5. DATA CLEANING VERIFICATION RESULT")
print("=" * 75)

checks = []


# Row count
checks.append(
    ("Processed rows exist", len(processed) > 0)
)


# Duplicates
checks.append(
    ("No duplicate rows after cleaning",
     duplicates_after == 0)
)


# Timestamp
checks.append(
    ("No invalid timestamps after cleaning",
     invalid_timestamps_after == 0)
)


# Severity
checks.append(
    ("Severity standardized",
     invalid_severity_after == 0)
)


# Event ID
checks.append(
    ("No duplicate event IDs",
     duplicate_event_ids == 0)
)


# Required columns
missing_required_columns = [
    column
    for column in required_columns
    if column not in processed.columns
]

checks.append(
    (
        "Required security event schema present",
        len(missing_required_columns) == 0
    )
)


for check_name, result in checks:

    print(
        f"{check_name}: "
        f"{'PASS' if result else 'FAIL'}"
    )


# ============================================================
# 20. FINAL STATUS
# ============================================================

all_passed = all(
    result
    for _, result in checks
)

print("\n" + "=" * 75)

if all_passed:

    print("DATA CLEANING VERIFICATION: PASS")

else:

    print("DATA CLEANING VERIFICATION: REVIEW REQUIRED")

print("=" * 75)


conn.close()