from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Configure database - Use SQLite for now to get the app running
database_url = os.environ.get('DATABASE_URL', 'sqlite:///local.db')

# If it's a PostgreSQL URL but we can't use it, fall back to SQLite
if database_url and database_url.startswith('postgres'):
    logger.warning("PostgreSQL detected but drivers not available. Falling back to SQLite.")
    database_url = 'sqlite:///local.db'

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User model for admin login
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Data model for Kali information
class KaliData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    hostname = db.Column(db.String(100))
    cpu_usage = db.Column(db.Float)
    memory_usage = db.Column(db.Float)
    disk_usage = db.Column(db.Float)
    network_activity = db.Column(db.Float)
    processes = db.Column(db.Integer)
    logged_in_users = db.Column(db.Integer)
    additional_info = db.Column(db.Text)

# Create tables and admin user
def initialize_database():
    with app.app_context():
        try:
            db.create_all()
            
            # Create default admin user if not exists
            if not User.query.filter_by(username='admin').first():
                admin = User(username='admin')
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                logger.info("Default admin user created")
                
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {str(e)}")

# Initialize the database when the app starts
initialize_database()

# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get recent data for dashboard
    recent_data = KaliData.query.order_by(KaliData.timestamp.desc()).limit(10).all()
    return render_template('dashboard.html', data=recent_data)

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
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/api/data', methods=['POST'])
def receive_data():
    # This endpoint will receive data from Kali Linux
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Create new data record
        new_data = KaliData(
            hostname=data.get('hostname'),
            cpu_usage=data.get('cpu_usage'),
            memory_usage=data.get('memory_usage'),
            disk_usage=data.get('disk_usage'),
            network_activity=data.get('network_activity'),
            processes=data.get('processes'),
            logged_in_users=data.get('logged_in_users'),
            additional_info=data.get('additional_info')
        )
        
        db.session.add(new_data)
        db.session.commit()
        
        logger.info(f"Data received from {data.get('hostname', 'unknown')}")
        return jsonify({'message': 'Data stored successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error storing data: {str(e)}")
        return jsonify({'error': 'Failed to store data'}), 500

@app.route('/api/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

@app.route('/test-db')
def test_db():
    try:
        # Try to query the database
        user_count = User.query.count()
        db_type = "SQLite" if "sqlite" in app.config['SQLALCHEMY_DATABASE_URI'] else "PostgreSQL"
        return f'{db_type} database connection successful! Found {user_count} users.'
    except Exception as e:
        return f'Database connection failed: {str(e)}'

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
