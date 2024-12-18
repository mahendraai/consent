import streamlit as st

st.title("🎈 My new app")
st.write(
    "Let's start building! For help and inspiration, head over to [docs.streamlit.io](https://docs.streamlit.io/)."
)

from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///saas_platform.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")  # user/admin

# Patient Data model
class PatientData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_name = db.Column(db.String(150), nullable=False)
    patient_email = db.Column(db.String(150), nullable=False)
    consent_status = db.Column(db.String(50), nullable=False, default="pending")
    organization_id = db.Column(db.Integer, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        role = request.form.get('role', 'user')

        if User.query.filter_by(email=email).first():
            return "Email already registered."

        new_user = User(username=username, email=email, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials."

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        patients = PatientData.query.filter_by(organization_id=current_user.id).all()
        return render_template('admin_dashboard.html', patients=patients)
    else:
        return render_template('user_dashboard.html')

@app.route('/add_patient', methods=['GET', 'POST'])
@login_required
def add_patient():
    if request.method == 'POST':
        patient_name = request.form['patient_name']
        patient_email = request.form['patient_email']
        consent_status = request.form['consent_status']

        new_patient = PatientData(patient_name=patient_name, patient_email=patient_email, consent_status=consent_status, organization_id=current_user.id)
        db.session.add(new_patient)
        db.session.commit()

        return redirect(url_for('dashboard'))

    return render_template('add_patient.html')

@app.route('/update_consent/<int:patient_id>', methods=['POST'])
@login_required
def update_consent(patient_id):
    patient = PatientData.query.get_or_404(patient_id)

    if request.form['consent_status']:
        patient.consent_status = request.form['consent_status']
        db.session.commit()

    return redirect(url_for('dashboard'))

@app.route('/api/patient_data', methods=['GET'])
@login_required
def api_patient_data():
    patients = PatientData.query.filter_by(organization_id=current_user.id).all()
    patient_list = [{
        'id': patient.id,
        'name': patient.patient_name,
        'email': patient.patient_email,
        'consent_status': patient.consent_status
    } for patient in patients]

    return jsonify(patient_list)

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
