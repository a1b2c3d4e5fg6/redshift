from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import json
import time
import psycopg
from psycopg import sql
import os
import re
from pathlib import Path
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix
import ssl
from OpenSSL import crypto

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')

# Handle proxy headers for HTTPS
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# PostgreSQL database configuration - enforce SSL
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://red_db_user:08PP2B2lSy2GAD5H7Jp51XRbrzldYOZB@dpg-d32s8gur433s73bavsvg-a.oregon-postgres.render.com/red_db')
if 'sslmode' not in DATABASE_URL:
    if '?' in DATABASE_URL:
        DATABASE_URL += '&sslmode=require'
    else:
        DATABASE_URL += '?sslmode=require'

# Force HTTPS in production
@app.before_request
def force_https():
    if os.environ.get('FLASK_ENV') == 'production':
        if request.headers.get('X-Forwarded-Proto') == 'http':
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login', next=request.url))
        
        # Verify user still exists in database
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        'SELECT id FROM users WHERE id = %s',
                        (session['user_id'],)
                    )
                    user = cur.fetchone()
            
            if not user:
                session.clear()
                flash('Your account no longer exists.', 'error')
                return redirect(url_for('login'))
                
        except Exception as e:
            print(f"Error checking user: {e}")
            session.clear()
            flash('Database error. Please log in again.', 'error')
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

# Database setup
def init_db():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                # Create users table
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create network_traffic table
                cur.execute('''
                    CREATE TABLE IF NOT EXISTS network_traffic (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        source TEXT NOT NULL,
                        dest TEXT NOT NULL,
                        protocol TEXT NOT NULL,
                        service TEXT,
                        content TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create default user if not exists
                cur.execute("SELECT id FROM users WHERE username = 'red'")
                if not cur.fetchone():
                    password_hash = generate_password_hash('hacker')
                    cur.execute(
                        "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                        ('red', 'red@example.com', password_hash)
                    )
            
            conn.commit()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {e}")

# Database connection helper
def get_db():
    try:
        conn = psycopg.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Error connecting to database: {e}")
        raise e

# Email validation function
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Generate self-signed SSL certificate
def generate_self_signed_cert(cert_file, key_file):
    # Create a key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    
    # Create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "Organization"
    cert.get_subject().OU = "Organizational Unit"
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)  # 10 years
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')
    
    # Save certificate and key
    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_file, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    
    print(f"Generated self-signed certificate: {cert_file}")

# Debug route to check database contents (remove in production)
@app.route('/debug/users')
def debug_users():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT * FROM users')
                users = cur.fetchall()
        
        users_list = []
        for user in users:
            users_list.append({
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'password_hash': user[3],
                'created_at': user[4]
            })
        
        return jsonify(users_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validate input
        errors = []
        
        if not username:
            errors.append('Username is required!')
        elif len(username) < 3:
            errors.append('Username must be at least 3 characters long!')
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append('Username can only contain letters, numbers, and underscores!')
            
        if not email:
            errors.append('Email is required!')
        elif not is_valid_email(email):
            errors.append('Please enter a valid email address!')
            
        if not password:
            errors.append('Password is required!')
        elif len(password) < 8:
            errors.append('Password must be at least 8 characters long!')
        elif password != confirm_password:
            errors.append('Passwords do not match!')
        
        # If there are errors, show them and return
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('register.html')
        
        # Check if user already exists
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        'SELECT id FROM users WHERE username = %s OR email = %s',
                        (username, email)
                    )
                    user = cur.fetchone()
            
            if user:
                flash('Username or email already exists!', 'error')
                return render_template('register.html')
            
            # Create new user
            password_hash = generate_password_hash(password)
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        'INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id',
                        (username, email, password_hash)
                    )
                    new_user_id = cur.fetchone()[0]
                conn.commit()
            
            print(f"New user created: {username} (ID: {new_user_id})")
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
                
        except Exception as e:
            flash('An error occurred during registration. Please try again.', 'error')
            print(f"Error during registration: {e}")
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to dashboard
    if 'user_id' in session:
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        'SELECT id FROM users WHERE id = %s',
                        (session['user_id'],)
                    )
                    user = cur.fetchone()
            
            if user:
                return redirect(url_for('dashboard'))
            else:
                session.clear()
        except Exception:
            session.clear()
    
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        next_page = request.args.get('next')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        'SELECT * FROM users WHERE username = %s OR email = %s',
                        (username, username)  # Allow login with either username or email
                    )
                    user = cur.fetchone()
            
            if user and check_password_hash(user[3], password):  # password_hash is at index 3
                session['user_id'] = user[0]  # id is at index 0
                session['username'] = user[1]  # username is at index 1
                flash('Login successful!', 'success')
                
                # Redirect to the requested page or dashboard
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Invalid username/email or password', 'error')
        except Exception as e:
            flash('Database error. Please try again.', 'error')
            print(f"Login error: {e}")
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get the latest network traffic data
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT * FROM network_traffic ORDER BY timestamp DESC LIMIT 50'
                )
                network_traffic = cur.fetchall()
        
        # Convert to list of dictionaries
        formatted_traffic = []
        for traffic in network_traffic:
            traffic_dict = {
                'id': traffic[0],
                'timestamp': traffic[1],
                'source': traffic[2],
                'dest': traffic[3],
                'protocol': traffic[4],
                'service': traffic[5],
                'content': traffic[6],
                'created_at': traffic[7]
            }
            
            # Convert timestamp if it's a string
            if isinstance(traffic_dict['timestamp'], str):
                try:
                    traffic_dict['timestamp'] = datetime.strptime(
                        traffic_dict['timestamp'], '%Y-%m-%d %H:%M:%S'
                    )
                except ValueError:
                    # If the format is different, try another common format
                    try:
                        traffic_dict['timestamp'] = datetime.fromisoformat(
                            traffic_dict['timestamp'].replace('Z', '+00:00')
                        )
                    except ValueError:
                        # If all else fails, keep the original string
                        pass
            formatted_traffic.append(traffic_dict)
        
        return render_template('dashboard.html', 
                             username=session['username'], 
                             network_traffic=formatted_traffic)
    except Exception as e:
        flash('Error loading dashboard data', 'error')
        print(f"Dashboard error: {e}")
        return render_template('dashboard.html', 
                             username=session['username'], 
                             network_traffic=[])

# API endpoint for receiving network traffic
@app.route('/api/network-traffic', methods=['POST'])
def receive_network_traffic():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'INSERT INTO network_traffic (source, dest, protocol, service, content, timestamp) VALUES (%s, %s, %s, %s, %s, %s)',
                    (data.get('source'), data.get('dest'), data.get('protocol'), 
                     data.get('service'), data.get('content'), data.get('timestamp', datetime.now(timezone.utc).isoformat()))
                )
            conn.commit()
        
        return jsonify({'message': 'Network traffic data stored successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to store data: {str(e)}'}), 500

# API endpoint to get latest network traffic
@app.route('/api/network-traffic/latest')
@login_required
def get_latest_network_traffic():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT * FROM network_traffic ORDER BY timestamp DESC LIMIT 50'
                )
                latest_traffic = cur.fetchall()
        
        # Convert to list of dictionaries
        traffic_data = []
        for t in latest_traffic:
            traffic_data.append({
                'id': t[0],
                'timestamp': t[1],
                'source': t[2],
                'dest': t[3],
                'protocol': t[4],
                'service': t[5],
                'content': t[6]
            })
        
        return jsonify(traffic_data)
    except Exception as e:
        return jsonify({'error': f'Failed to fetch data: {str(e)}'}), 500

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Health check endpoint for Render
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

# Initialize database on app start
init_db()

# For Gunicorn production deployment
application = app

if __name__ == '__main__':
    # SSL context for development
    ssl_context = None
    
    # Create ssl directory if it doesn't exist
    Path("ssl").mkdir(exist_ok=True)
    
    # Generate self-signed certificates if they don't exist
    cert_path = "ssl/cert.pem"
    key_path = "ssl/key.pem"
    
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        generate_self_signed_cert(cert_path, key_path)
    
    ssl_context = (cert_path, key_path)
    
    app.run(
        debug=True, 
        host='0.0.0.0', 
        port=5000, 
        ssl_context=ssl_context
    )
