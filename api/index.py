"""
Vercel Serverless Entrypoint for PhishLens Backend
Exposes the Flask WSGI application for Vercel Python runtime.
"""

import os
import sys

# Ensure the project root and backend directory are in the Python path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_dir = os.path.join(root_dir, "backend")
sys.path.insert(0, root_dir)
sys.path.insert(0, backend_dir)

from backend.app import app

# Vercel WSGI entry point
# Flask app object is exported as 'app'
if __name__ == "__main__":
    app.run()
