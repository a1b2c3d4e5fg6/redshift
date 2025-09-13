from flask import Flask, render_template
from datetime import datetime
import os

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html', current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route('/health')
def health_check():
    return 'Server is running successfully!'

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
