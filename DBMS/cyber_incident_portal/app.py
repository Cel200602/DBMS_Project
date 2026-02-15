
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False



db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Database Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'user' or 'admin'
    full_name = db.Column(db.String(150))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(150))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default='Reported')  # Reported, Verified, Handling, Closed
    priority = db.Column(db.String(50), default='Normal')  # Normal, High, Critical
    risk_level = db.Column(db.String(50), default='Low')   # Low, Medium, High
    handling_duration = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('incidents', lazy=True))

class IncidentUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)
    update_text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    incident = db.relationship('Incident', backref=db.backref('updates', lazy=True))

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('notifications', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes (Placeholders) ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# User Routes
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        return redirect(url_for('index'))
    # Fetch unread notifications
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.timestamp.desc()).all()
    return render_template('user/dashboard.html', notifications=notifications)

@app.route('/user/profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    if request.method == 'POST':
        current_user.full_name = request.form.get('full_name')
        current_user.phone = request.form.get('phone')
        new_password = request.form.get('password')
        if new_password:
            current_user.set_password(new_password)
        db.session.commit()
        flash('Profile updated successfully')
    return render_template('user/profile.html')

@app.route('/user/incident_login', methods=['GET', 'POST'])
@login_required
def incident_login():
    # As per requirements: Ask username + password, Validate -> redirect to incidents.html
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == current_user.username and current_user.check_password(password):
            session['incident_access_granted'] = True
            return redirect(url_for('user_incidents'))
        else:
            flash('Invalid credentials for incident access')
    return render_template('user/incident_login.html')

@app.route('/user/incidents')
@login_required
def user_incidents():
    if not session.get('incident_access_granted'):
        return redirect(url_for('incident_login'))
    incidents = Incident.query.filter_by(user_id=current_user.id).all()
    return render_template('user/incidents.html', incidents=incidents)

@app.route('/user/report', methods=['GET', 'POST'])
@login_required
def report_incident():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        new_incident = Incident(title=title, description=description, user_id=current_user.id)
        db.session.add(new_incident)
        db.session.commit()
        flash('Incident reported successfully')
        return redirect(url_for('user_dashboard'))
    return render_template('user/report.html') # Need to create this if not in list, but user/incidents has list, maybe a modal or separate page? Prompt says "My Incidents -> incidents.html", doesn't explicitly mention a separate report page, but logically needed. I'll add a report form in dashboard or separate.

@app.route('/user/status/<int:id>')
@login_required
def incident_status(id):
    incident = Incident.query.get_or_404(id)
    if incident.user_id != current_user.id:
        flash('Access denied')
        return redirect(url_for('user_dashboard'))
    updates = IncidentUpdate.query.filter_by(incident_id=id).order_by(IncidentUpdate.timestamp.desc()).all()
    return render_template('user/status.html', incident=incident, updates=updates)

@app.route('/user/rank')
@login_required
def user_rank():
    # Rank based on Priority, Risk Level, Handling Duration.
    # Simple sorting for now.
    incidents = Incident.query.order_by(Incident.priority.desc(), Incident.risk_level.desc()).all()
    return render_template('user/rank.html', incidents=incidents)

# Admin Routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    
    # Fetch data for dashboard tabs
    users = User.query.all()
    incidents = Incident.query.all()
    
    # Check for active tab from query param
    active_tab = request.args.get('tab', 'IncidentEntry')
    
    return render_template('admin/dashboard.html', users=users, incidents=incidents, active_tab=active_tab)

@app.route('/api/incident/<int:id>')
@login_required
def api_incident(id):
    if current_user.role != 'admin': return {'error': 'Unauthorized'}, 403
    incident = Incident.query.get(id)
    if incident:
        return {
            'id': incident.id,
            'title': incident.title,
            'description': incident.description,
            'user': incident.user.username,
            'status': incident.status,
            'priority': incident.priority
        }
    return {'error': 'Incident not found'}, 404

@app.route('/admin/incident_entry', methods=['GET', 'POST'])
@login_required
def admin_incident_entry():
    if current_user.role != 'admin': return redirect(url_for('index'))
    if request.method == 'POST':
        incident_id = request.form.get('incident_id')
        status = request.form.get('status')
        priority = request.form.get('priority')
        risk_level = request.form.get('risk_level')
        remarks = request.form.get('remarks')
        
        incident = Incident.query.get(incident_id)
        if incident:
            incident.status = status
            incident.priority = priority
            incident.risk_level = risk_level
            # Estimate handling duration logic could go here or be manual
            
            update = IncidentUpdate(incident_id=incident.id, update_text=remarks)
            db.session.add(update)
            
            # Create notification for user
            notif = Notification(user_id=incident.user_id, message=f"Incident '{incident.title}' updated: {status}")
            db.session.add(notif)
            
            db.session.commit()
            flash('Incident updated')
            return redirect(url_for('admin_dashboard', tab='IncidentEntry')) # Stay on tab

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/records', methods=['GET', 'POST'])
@login_required
def admin_records():
    # This route is now mostly for display in dashboard, but if we had edit logic it would go here
    return redirect(url_for('admin_dashboard', tab='Records'))

@app.route('/admin/rank')
@login_required
def admin_rank():
    return redirect(url_for('admin_dashboard', tab='Rank'))

@app.route('/admin/profile', methods=['GET', 'POST'])
@login_required
def admin_profile():
    if current_user.role != 'admin': return redirect(url_for('index'))
    if request.method == 'POST':
        current_user.full_name = request.form.get('full_name')
        new_password = request.form.get('password')
        if new_password:
            current_user.set_password(new_password)
        db.session.commit()
        flash('Admin profile updated')
        return redirect(url_for('admin_dashboard', tab='Profile'))
    return redirect(url_for('admin_dashboard'))


# --- Main ---

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create default admin if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin', full_name='System Admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created.")
            
    app.run(debug=True)
