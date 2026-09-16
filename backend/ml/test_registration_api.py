import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.app import app
from backend.database.db import SessionLocal
from backend.models.database_models import User

def test_registration_endpoints():
    print("=" * 70)
    print("TESTING ACCOUNT CREATION & PASSWORD RECOVERY ENDPOINTS")
    print("=" * 70)

    client = app.test_client()

    # Clear prior test users if exists
    db = SessionLocal()
    try:
        test_user = db.query(User).filter(User.username == "shreya_test").first()
        if test_user:
            db.delete(test_user)
            db.commit()
    finally:
        db.close()

    # 1. Create Valid User
    res_valid = client.post("/register", json={
        "email": "shreya_test@gmail.com",
        "username": "shreya_test",
        "password": "password123",
        "confirm_password": "password123"
    })
    assert res_valid.status_code == 201
    valid_data = res_valid.get_json()
    assert valid_data["user"]["username"] == "shreya_test"
    assert valid_data["user"]["email"] == "shreya_test@gmail.com"
    assert valid_data["user"]["role"] == "Tier 2 Security Analyst"
    print("1. Successfully registered new analyst account")

    # 2. Try Duplicate username check
    res_dup_username = client.post("/register", json={
        "email": "another_email@gmail.com",
        "username": "shreya_test",
        "password": "password123",
        "confirm_password": "password123"
    })
    assert res_dup_username.status_code == 400
    assert "USERNAME is already registered" in res_dup_username.get_json()["error"]
    print("2. Successfully rejected duplicate username registration")

    # 3. Try Duplicate email check
    res_dup_email = client.post("/register", json={
        "email": "shreya_test@gmail.com",
        "username": "another_user",
        "password": "password123",
        "confirm_password": "password123"
    })
    assert res_dup_email.status_code == 400
    assert "EMAIL is already registered" in res_dup_email.get_json()["error"]
    print("3. Successfully rejected duplicate email registration")

    # 4. Validation Checks
    res_mismatch = client.post("/register", json={
        "email": "shreya_test2@gmail.com",
        "username": "shreya_test2",
        "password": "password123",
        "confirm_password": "differentpassword"
    })
    assert res_mismatch.status_code == 400
    assert "Passwords do not match" in res_mismatch.get_json()["error"]
    print("4. Successfully validated password mismatch")

    res_short_pass = client.post("/register", json={
        "email": "shreya_test2@gmail.com",
        "username": "shreya_test2",
        "password": "123",
        "confirm_password": "123"
    })
    assert res_short_pass.status_code == 400
    assert "Password must be at least 6 characters" in res_short_pass.get_json()["error"]
    print("5. Successfully validated password minimum length")

    # 4. Try Login with new account
    login_res = client.post("/login", json={
        "username": "shreya_test",
        "password": "password123"
    })
    assert login_res.status_code == 200
    print("6. Successfully authenticated new user session")

    # 5. Forgot Password directive check
    forgot_res = client.post("/forgot-password", json={
        "username": "shreya_test",
        "email": "shreya_test@gmail.com"
    })
    assert forgot_res.status_code == 200
    assert "contact your SOC System Administrator" in forgot_res.get_json()["message"]
    print("7. Verified honest forgot password recovery notification")

    # Clean up test user
    db = SessionLocal()
    try:
        test_user = db.query(User).filter(User.username == "shreya_test").first()
        if test_user:
            db.delete(test_user)
            db.commit()
    finally:
        db.close()
    print("8. Cleaned up temporary test user")

    print("\nALL ACCOUNT CREATION & RECOVERY TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_registration_endpoints()
