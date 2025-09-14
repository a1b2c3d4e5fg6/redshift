from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import json
import time
import os
import re
import psycopg2
from psycopg2.extras import RealDictCursor
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')

# Database configuration - using PostgreSQL instead of SQLite
def get_db_connection():
    try:
        # For Render.com PostgreSQL database
        conn = psycopg2.connect(
            host=os.environ.get('DB_HOST', 'localhost'),
            database=os.environ.get('DB_NAME', 'red_db'),
            user=os.environ.get('DB_USER', 'postgres'),
            password=os.environ.get('DB_PASSWORD', ''),
            port=os.environ.get('DB_PORT', '5432')
        )
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login', next=request.url))
        
        # Verify user still exists in database
        conn = get_db_connection()
        if conn:
            try:
                cur = conn.cursor(cursor_factory=RealDictCursor)
                cur.execute('SELECT id FROM users WHERE id = %s', (session['user_id'],))
                user = cur.fetchone()
                cur.close()
                conn.close()
                
                if not user:
                    session.clear()
                    flash('Your account no longer exists.', 'error')
                    return redirect(url_for('login'))
            except Exception as e:
                print(f"Error checking user: {e}")
                flash('Database error. Please try again.', 'error')
                return redirect(url_for('login'))
        else:
            flash('Database connection error. Please try again.', 'error')
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

# Database setup
def init_db():
    conn = get_db_connection()
    if not conn:
        print("Failed to connect to database")
        return
        
    try:
        cur = conn.cursor()
        
        # Create users table
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
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
        
        # Create default admin user if not exists
        cur.execute("SELECT id FROM users WHERE username = 'admin'")
        if not cur.fetchone():
            password_hash = generate_password_hash('admin123')
            cur.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                ('admin', 'admin@example.com', password_hash)
            )
        
        conn.commit()
        cur.close()
        conn.close()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {e}")

# Initialize database
init_db()

# Email validation function
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Debug route to check database contents
@app.route('/debug/users')
def debug_users():
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM users')
        users = cur.fetchall()
        cur.close()
        conn.close()
        
        return jsonify([dict(user) for user in users])
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
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again.', 'error')
            return render_template('register.html')
            
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute(
                'SELECT id FROM users WHERE username = %s OR email = %s',
                (username, email)
            )
            user = cur.fetchone()
            
            if user:
                flash('Username or email already exists!', 'error')
                cur.close()
                conn.close()
                return render_template('register.html')
            
            # Create new user
            password_hash = generate_password_hash(password)
            cur.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id',
                (username, email, password_hash)
            )
            
            new_user_id = cur.fetchone()['id']
            conn.commit()
            
            cur.close()
            conn.close()
            
            print(f"New user created: {username} (ID: {new_user_id})")
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
                
        except Exception as e:
            flash('An error occurred during registration. Please try again.', 'error')
            print(f"Error during registration: {e}")
            try:
                cur.close()
                conn.close()
            except:
                pass
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to dashboard
    if 'user_id' in session:
        # Verify user still exists in database
        conn = get_db_connection()
        if conn:
            try:
                cur = conn.cursor(cursor_factory=RealDictCursor)
                cur.execute('SELECT id FROM users WHERE id = %s', (session['user_id'],))
                user = cur.fetchone()
                cur.close()
                conn.close()
                
                if user:
                    return redirect(url_for('dashboard'))
            except:
                pass
        session.clear()
    
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        next_page = request.args.get('next')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again.', 'error')
            return render_template('login.html')
            
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute(
                'SELECT * FROM users WHERE username = %s OR email = %s',
                (username, username)  # Allow login with either username or email
            )
            user = cur.fetchone()
            cur.close()
            conn.close()
            
            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
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
    conn = get_db_connection()
    if not conn:
        flash('Database connection error. Please try again.', 'error')
        return redirect(url_for('login'))
        
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM network_traffic ORDER BY timestamp DESC LIMIT 50')
        network_traffic = cur.fetchall()
        cur.close()
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
    except Exception as e:
        flash('Error loading dashboard data.', 'error')
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
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO network_traffic (source, dest, protocol, service, content, timestamp) VALUES (%s, %s, %s, %s, %s, %s)',
            (data.get('source'), data.get('dest'), data.get('protocol'), 
             data.get('service'), data.get('content'), data.get('timestamp', datetime.now(timezone.utc).isoformat()))
        )
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'message': 'Network traffic data stored successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to store data: {str(e)}'}), 500

# API endpoint to get latest network traffic
@app.route('/api/network-traffic/latest')
@login_required
def get_latest_network_traffic():
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
            
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM network_traffic ORDER BY timestamp DESC LIMIT 50')
        latest_traffic = cur.fetchall()
        cur.close()
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
