import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'cyber_incident_portal')))

from app import app, db, User, Incident
from flask import url_for

def verify():
    print("Verifying Cyber Incident Reporting Portal Setup...")
    
    # 1. Check Database File
    db_path = os.path.join(os.path.dirname(__file__), 'cyber_incident_portal', 'db.sqlite')
    if os.path.exists(db_path):
        print(f"[PASS] Database file found at {db_path}")
    else:
        print(f"[FAIL] Database file NOT found at {db_path}")
        # Initialize db if not exists (simulate app run)
        with app.app_context():
            db.create_all()
            print("[INFO] Database initialized.")

    with app.app_context():
        # 2. Check Admin User
        admin = User.query.filter_by(role='admin').first()
        if admin:
            print(f"[PASS] Admin user found: {admin.username}")
        else:
            print("[FAIL] Admin user NOT found. Creating default admin...")
            admin = User(username='admin', role='admin', full_name='System Admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("[INFO] Default admin created.")

        # 3. Create Test User if not exists
        test_user = User.query.filter_by(username='testuser').first()
        if not test_user:
            test_user = User(username='testuser', role='user', full_name='Test User')
            test_user.set_password('user123')
            db.session.add(test_user)
            db.session.commit()
            print("[INFO] Test user 'testuser' created.")
        else:
            print(f"[PASS] Test user found: {test_user.username}")

        # 4. Check Routes (Basic check)
        with app.test_client() as client:
            resp = client.get('/')
            if resp.status_code == 302: # Redirects to login
                print("[PASS] Route '/' redirects (likely to login).")
            else:
                print(f"[WARN] Route '/' returned {resp.status_code}")

            resp = client.get('/login')
            if resp.status_code == 200:
                print("[PASS] Route '/login' is accessible.")
            else:
                print(f"[FAIL] Route '/login' returned {resp.status_code}")

    print("\nVerification Complete.")

if __name__ == '__main__':
    verify()
