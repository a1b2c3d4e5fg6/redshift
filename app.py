from flask import Flask, render_template,request, redirect,url_for, session, flash, jsonify
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

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://red_db_user:08PP2B2lSy2GAD5H7Jp51XRbrzldYOZB@dpg-d32s8gur433s73bavsvg-a.oregon-postgres.render.com/red_db')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('please log in to access this page.', 'error')
            return redirect(url_for('login', next=request.url))
        
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        'SELECT id from users WHERE id = %s',
                        (session['user_id'],)
                        
                    )
                    user =cur.fetchone()
            if not user:
                session.clear()
                flash('Your account no longer exists.', 'error')
                return redirect(url_for('login'))
        except Exception as e:
            print(f'error checking user:{e}')
            session.clear()
            flash('Database error. please log in again.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def init_db():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute('''
                   CREATE TABLE IF NOT EXISTS users (
                      id serial primary key,
                      username TEXT UNIQUE NOT NULL,
                      email TEXT UNIQUE NOT NULL,
                       password_hash text not NULL,
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                       )
                       ''')
    
                cur.execute('''
                   CREATE TABLE if not exists network_traffic (
                      id integer primary key,
                      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      source text not NULL,
                      dest text not null,
                      protocol text not null ,
                      service text,
                      content text,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP 
                      )
                      ''')
                cur.execute("SELECT id from users where username ='red'")
                if not cur.fetchone():
                  password_hash = generate_password_hash('hacker')
                  cur.execute(
                   "INSERT INTO users(username, email,password_hash) values(%s, %s, %s)",
                   ('red', 'red@example.com', password_hash)
            
                    )
        
            conn.commit()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {e}")
        

def get_db():
    
    try:
        conn = psycopg.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Error connecting to database: {e}")
        raise e 
    
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None
@app.route('/debug/users')
def debug_users():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute('select * from users')
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
        
        errors =[]
        
        if not username:
            errors.append('Username is required!')
        elif len(username)<3:
            errors.append('username must be at least 3 characters long')
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append('username can only contain letters, numbers and underscores')
        if not email:
                errors.append('email is required!')
        elif not is_valid_email(email):
            errors.append('Please enter valid email address')
       
        if not password:
                errors.append('password is required!')
        elif len(password)<8:
            errors.append('password must be at least 8 characters long')
        elif password != confirm_password:
            errors.append('password not match')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('register.html')
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        'SELECT id FROM users WHERE username = %s OR email = %s',
                        (username,email)
                    )
                    user=cur.fetchone()
            if user:
              flash('Username or email already exists!', 'error')
              return render_template('register.html')
        
            password_hash = generate_password_hash(password)
            with get_db() as conn:
                  with conn.cursor() as cur:
                     cur.execute(
                        'INSERT INTO users (username, email, password_hash) values(%s, %s, %s)RETURNING id',
                         (username, email, password_hash)
                      )
                     new_user_id = cur.fetchone()[0]
                  conn.commit()
            print(f"new user created: {username} (ID: {new_user_id})")
            flash('Registration successful! please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(' error occurred during registration. please try again.', 'error')
            print(f"error during registration: {e}")
            return render_template('register.html')
    return render_template('register.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                                'select id from users where id = %s',
                                (session['user_id'],)
                                )
                    user = cur.fetchone()
            if user:
                return redirect(url_for('dashboard'))
            else:
                session.clear()
        except Exception as e:
            session.clear()
    if request.method =='POST':
        username = request.form['username'].strip()
        password =request.form['password']
        next_page = request.args.get('next')
        
        if not username or not password:
            flash('please enter both username and password', 'error')
            return render_template('login.html')
        
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        'select * from users where username = %s OR email = %s',
                        (username,username)
                    )
                    user = cur.fetchone()
            
            if user and check_password_hash(user[3], password):
                session['user_id'] = user[0]
                session['username'] = user[1]
                flash('Login successful ', 'success')
                
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('Invalid username/email or password', 'error')
        except Exception as e:
            flash('Database error. please try again', 'error')
            print(f"Login ettor:{e}")
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        'select * from network_traffic ORDER BY timestamp DESC LIMIT 50 '
                    )
                    network_traffic = cur.fetchall()
        formatted_traffic= []
        for traffic in network_traffic:
            traffic_dict = {
                'id': traffic[0],
                'timestamp':traffic[1],
                'source': traffic[2],
                'dest':traffic[3],
                'protocol': traffic[4],
                'service':traffic[5],
                'content': traffic[6],
                'created_at':traffic[7]
            }
            if isinstance(traffic_dict['timestamp'], str):
                try:
                    traffic_dict['timestamp'] = datetime.strptime(
                        traffic_dict['timestamp'], '%Y-%m-%d %H:%M:%S'
                    )
                except ValueError:
                    
                    try:
                        traffic_dict['timestamp'] = datetime.fromisoformat(
                            traffic_dict['timestamp'].replace('Z', '+00:00')
                        )
                    except ValueError:
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
     
@app.route('/api/network-traffic', methods=['POST'])
def receive_network_traffic():
    try:
        data = request.get_json()
        
        if not data:
             return jsonify({'error': 'No data provided'}), 400
         
        with get_db() as conn:
            with conn.cursor() as cur:
                
                cur.execute(
                   'INSERT INTO network_traffic (source,dest, protocol, service, content, timestamp)values(%s, %s, %s, %s, %s, %s)',
                    (data.get('source'), data.get('dest'), data.get('protocol'),
                    data.get('service'), data.get('content'), data.get('timestamp', datetime.now(timezone.utc).isoformat()))
             )
            conn.commit()

        return jsonify({'message': 'Network traffic data stored successlly'}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to store data: {str(e)}'}), 500
@app.route('/api/network-traffic/latest')
@login_required
def get_latest_network_traffic():
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
               cur.execute(
                  'SELECT * FROM network_traffic ORDER BY timestamp DESC LIMIT 50'
                  )
               latest_traffic=cur.fetchall()
        
        traffic_data =[]
        for t in latest_traffic:
            traffic_data.append({
                'id':t[0],
                'timestamp': t[1],
                'source': t[2],
                'dest': t[3],
                'protocol': t[4],
                'service': t[5],
                'content': t[6]
            })
            
        return jsonify(traffic_data)
    except Exception as e:
        return jsonify({'error': f'Failed to fetch data:{str(e)}'}), 500
    
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})         

init_db()     
application = app

if __name__=='__main__':
       app.run(debug=True, host='0.0.0.0', port=5000) 
