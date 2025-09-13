from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a random secret key

# Hardcoded PostgreSQL connection details
DB_USER = 'red_db_user'
DB_PASSWORD = '08PP2B2lSy2GAD5H7Jp51XRbrzldYOZB'
DB_HOST = 'dpg-d32s8gur433s73bavsvg-a.oregon-postgres.render.com'
DB_NAME = 'red_db'

# Configure PostgreSQL database
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Network Traffic model - ADDED
class NetworkTraffic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(255), nullable=False)
    dest = db.Column(db.String(255), nullable=False)
    protocol = db.Column(db.String(50), nullable=False)
    service = db.Column(db.String(100))
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<NetworkTraffic {self.source} -> {self.dest} ({self.protocol})>'

# Initialize database
with app.app_context():
    db.create_all()
    
    # Create default admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'error')
            return render_template('register.html')
        
        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating user. Please try again.', 'error')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

# Updated dashboard route - ADDED network traffic data
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get the latest network traffic data
    network_traffic = NetworkTraffic.query.order_by(NetworkTraffic.timestamp.desc()).limit(50).all()
    
    return render_template('dashboard.html', 
                         username=session['username'], 
                         network_traffic=network_traffic)

# API endpoint for receiving network traffic - ADDED
@app.route('/api/network-traffic', methods=['POST'])
def receive_network_traffic():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Create new network traffic record
        new_traffic = NetworkTraffic(
            source=data.get('source'),
            dest=data.get('dest'),
            protocol=data.get('protocol'),
            service=data.get('service'),
            content=data.get('content')
        )
        
        # If timestamp is provided, use it
        if 'timestamp' in data:
            new_traffic.timestamp = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        
        db.session.add(new_traffic)
        db.session.commit()
        
        return jsonify({'message': 'Network traffic data stored successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to store data: {str(e)}'}), 500

# Route to add sample data for testing - ADDED
@app.route('/add-sample-data')
def add_sample_data():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Add some sample data for testing
    sample_data = NetworkTraffic(
        source="192.168.1.100",
        dest="8.8.8.8",
        protocol="TCP",
        service="DNS",
        content="Query: example.com"
    )
    
    db.session.add(sample_data)
    db.session.commit()
    
    flash('Sample data added successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
