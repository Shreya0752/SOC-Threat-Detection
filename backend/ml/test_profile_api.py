import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.app import app
from backend.database.db import SessionLocal
from backend.models.database_models import User

def test_profile_endpoints():
    print("=" * 70)
    print("TESTING USER PROFILE CHANGE ENDPOINTS")
    print("=" * 70)

    client = app.test_client()

    # Step 1: Login
    login_res = client.post("/login", json={"username": "Shreya M", "password": "soc12345"})
    assert login_res.status_code == 200, "Login failed"
    print("1. Login successful")

    # Step 2: Update Username to new value
    update_res = client.post("/profile/update-username", json={"new_username": "new_analyst"})
    assert update_res.status_code == 200, "Update username failed"
    print("2. Changed username to 'new_analyst'")

    # Step 3: Verify /me returns new username
    me_res = client.get("/me")
    assert me_res.status_code == 200
    me_data = me_res.get_json()
    assert me_data["user"]["username"] == "new_analyst", "Username not updated in session"
    print("3. Verified /me returns 'new_analyst'")

    # Step 4: Login with old username should FAIL, and new username should PASS
    login_old = client.post("/login", json={"username": "Shreya M", "password": "soc12345"})
    assert login_old.status_code == 401
    print("4. Verified login with old username fails as expected")

    login_new = client.post("/login", json={"username": "new_analyst", "password": "soc12345"})
    assert login_new.status_code == 200
    print("5. Verified login with new username succeeds")

    # Step 5: Update Password
    pass_res = client.post("/profile/update-password", json={
        "current_password": "soc12345",
        "new_password": "newpassword123",
        "confirm_password": "newpassword123"
    })
    assert pass_res.status_code == 200, "Password update failed"
    print("6. Changed password successfully")

    # Step 6: Verify login with new password works
    login_pass = client.post("/login", json={"username": "new_analyst", "password": "newpassword123"})
    assert login_pass.status_code == 200
    print("7. Verified login with new password succeeds")

    # Step 7: Restore username and password to defaults to keep seeding correct
    restore_username = client.post("/profile/update-username", json={"new_username": "Shreya M"})
    assert restore_username.status_code == 200
    restore_pass = client.post("/profile/update-password", json={
        "current_password": "newpassword123",
        "new_password": "soc12345",
        "confirm_password": "soc12345"
    })
    assert restore_pass.status_code == 200
    print("8. Restored demo credentials successfully")

    print("\nALL USER PROFILE ENDPOINT TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_profile_endpoints()
