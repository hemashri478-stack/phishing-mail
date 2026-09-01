#!/usr/bin/env python3
"""
PhishLens Cyber Defense Dashboard Server
Serves the security operations dashboard on port 8080.
"""

import os
from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=DASHBOARD_DIR)
CORS(app)

@app.route('/')
def index():
    return send_from_directory(DASHBOARD_DIR, 'index.html')

@app.route('/<path:filename>')
def serve_file(filename):
    return send_from_directory(DASHBOARD_DIR, filename)

@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "service": "PhishLens Cyber Defense Dashboard",
        "version": "2.0.0"
    })

if __name__ == '__main__':
    print("🛡️ PhishLens Cyber Defense Dashboard Server")
    print("=" * 50)
    print(f"Serving dashboard from: {DASHBOARD_DIR}")
    print("Access the dashboard at: http://localhost:8080")
    print("=" * 50)
    app.run(host='0.0.0.0', port=8080, debug=False)