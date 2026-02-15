
from cyber_incident_portal.app import app, db, User

def create_test_user():
    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        if user:
            print("User 'testuser' already exists.")
            # Update password just in case
            user.set_password('user123')
            db.session.commit()
            print("Password updated.")
        else:
            print("Creating 'testuser'...")
            new_user = User(username='testuser', role='user', full_name='Test User', email='test@example.com')
            new_user.set_password('user123')
            db.session.add(new_user)
            db.session.commit()
            print("User created.")

if __name__ == '__main__':
    create_test_user()
