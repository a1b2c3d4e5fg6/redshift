from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import json
import time
import sqlite3
import os
import re
from pathlib import Path
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')  # Use environment variable for security

# Use SQLite instead of PostgreSQL to avoid driver issues
DB_PATH = Path('app.db')

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login', next=request.url))
        
        # Verify user still exists in database
        conn = get_db()
        user = conn.execute(
            'SELECT id FROM users WHERE id = ?',
            (session['user_id'],)
        ).fetchone()
        conn.close()
        
        if not user:
            session.clear()
            flash('Your account no longer exists.', 'error')
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

# Database setup
def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Create users table
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create network_traffic table
        c.execute('''
            CREATE TABLE IF NOT EXISTS network_traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source TEXT NOT NULL,
                dest TEXT NOT NULL,
                protocol TEXT NOT NULL,
                service TEXT,
                content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create default admin user if not exists
        c.execute("SELECT id FROM users WHERE username = 'admin'")
        if not c.fetchone():
            password_hash = generate_password_hash('admin123')
            c.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                ('admin', 'admin@example.com', password_hash)
            )
        
        conn.commit()
        conn.close()
        print(f"Database initialized successfully at {DB_PATH.absolute()}")
    except Exception as e:
        print(f"Error initializing database: {e}")

# Initialize database
init_db()

# Database connection helper
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Email validation function
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Debug route to check database contents (remove in production)
@app.route('/debug/users')
def debug_users():
    try:
        conn = get_db()
        users = conn.execute('SELECT * FROM users').fetchall()
        conn.close()
        
        users_list = []
        for user in users:
            users_list.append(dict(user))
        
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
        conn = get_db()
        user = conn.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            (username, email)
        ).fetchone()
        
        if user:
            flash('Username or email already exists!', 'error')
            conn.close()
            return render_template('register.html')
        
        # Create new user
        password_hash = generate_password_hash(password)
        try:
            conn.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (username, email, password_hash)
            )
            conn.commit()
            
            # Get the newly created user ID
            new_user = conn.execute(
                'SELECT id FROM users WHERE username = ?',
                (username,)
            ).fetchone()
            
            conn.close()
            
            if new_user:
                print(f"New user created: {username} (ID: {new_user['id']})")
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Registration failed. Please try again.', 'error')
                return render_template('register.html')
                
        except sqlite3.IntegrityError as e:
            flash('Username or email already exists!', 'error')
            conn.close()
            print(f"Integrity error during registration: {e}")
            return render_template('register.html')
        except Exception as e:
            flash('An error occurred during registration. Please try again.', 'error')
            conn.close()
            print(f"Error during registration: {e}")
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to dashboard
    if 'user_id' in session:
        # Verify user still exists in database
        conn = get_db()
        user = conn.execute(
            'SELECT id FROM users WHERE id = ?',
            (session['user_id'],)
        ).fetchone()
        conn.close()
        
        if user:
            return redirect(url_for('dashboard'))
        else:
            session.clear()
    
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        next_page = request.args.get('next')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?',
            (username, username)  # Allow login with either username or email
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            
            # Redirect to the requested page or dashboard
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username/email or password', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required  # This decorator ensures user is logged in
def dashboard():
    # Get the latest network traffic data
    conn = get_db()
    network_traffic = conn.execute(
        'SELECT * FROM network_traffic ORDER BY timestamp DESC LIMIT 50'
    ).fetchall()
    conn.close()
    
    # Convert string timestamps to datetime objects
    formatted_traffic = []
    for traffic in network_traffic:
        traffic_dict = dict(traffic)
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

# API endpoint for receiving network traffic
@app.route('/api/network-traffic', methods=['POST'])
def receive_network_traffic():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        conn = get_db()
        conn.execute(
            'INSERT INTO network_traffic (source, dest, protocol, service, content, timestamp) VALUES (?, ?, ?, ?, ?, ?)',
            (data.get('source'), data.get('dest'), data.get('protocol'), 
             data.get('service'), data.get('content'), data.get('timestamp', datetime.now(timezone.utc).isoformat()))
        )
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Network traffic data stored successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to store data: {str(e)}'}), 500

# API endpoint to get latest network traffic
@app.route('/api/network-traffic/latest')
@login_required  # Protect API endpoints too
def get_latest_network_traffic():
    try:
        conn = get_db()
        latest_traffic = conn.execute(
            'SELECT * FROM network_traffic ORDER BY timestamp DESC LIMIT 50'
        ).fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        traffic_data = []
        for t in latest_traffic:
            traffic_data.append({
                'id': t['id'],
                'timestamp': t['timestamp'],
                'source': t['source'],
                'dest': t['dest'],
                'protocol': t['protocol'],
                'service': t['service'],
                'content': t['content']
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

# For Gunicorn production deployment
application = app

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
