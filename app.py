from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import json
import time
import psycopg2
from psycopg2 import sql
import os
import re
from pathlib import Path
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')

# PostgreSQL database configuration - enforce SSL
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://red_db_user:08PP2B2lSy2GAD5H7Jp51XRbrzldYOZB@dpg-d32s8gur433s73bavsvg-a.oregon-postgres.render.com/red_db')
if 'sslmode' not in DATABASE_URL:
    if '?' in DATABASE_URL:
        DATABASE_URL += '&sslmode=require'
    else:
        DATABASE_URL += '?sslmode=require'

# Enforce HTTPS in production
@app.before_request
def enforce_https():
    # Skip HTTPS enforcement for health checks (used by Render)
    if request.path == '/health':
        return
    
    # Check if running in production (Render sets RENDER environment variable)
    if os.environ.get('RENDER') or os.environ.get('FLASK_ENV') == 'production':
        # Check header set by proxy (like Render)
        if request.headers.get('X-Forwarded-Proto') == 'http':
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)

# ... [Rest of your code remains unchanged until the health check route] ...

# Health check endpoint for Render
@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

# Initialize database on app start
init_db()

# For Gunicorn production deployment
application = app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
