from functools import wraps
from urllib.parse import urlparse

from flask import request, jsonify, session
from flask_wtf.csrf import validate_csrf

from .global_vars import ALLOW_PUBLIC_API_ACCESS


# Authentication decorators for admin-required routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session or not session['admin']:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)

    return decorated_function


# Add this new decorator function after the existing decorators
# Authentication decorator for API-restricted routes
def api_access_control(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Always allow access if public mode is on
        if ALLOW_PUBLIC_API_ACCESS:
            # If it's a safe method (GET, HEAD, OPTIONS), allow
            if request.method in ('GET', 'HEAD', 'OPTIONS'):
                return f(*args, **kwargs)
            # If unsafe (POST, PUT, DELETE), validate CSRF token
            try:
                csrf_token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
                validate_csrf(csrf_token)
            except Exception:
                return jsonify({"error": "CSRF token missing or invalid"}), 403
            return f(*args, **kwargs)

        # Public mode is off — fallback to restricted access
        referer = request.headers.get('Referer', '')
        origin_matches = referer and urlparse(referer).netloc == urlparse(request.host_url).netloc
        is_admin = session.get('admin', False)

        # Allow if admin or from same origin (e.g. browser request from frontend)
        if is_admin or origin_matches:
            if request.method in ('POST', 'PUT', 'DELETE'):
                try:
                    csrf_token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
                    validate_csrf(csrf_token)
                except Exception:
                    return jsonify({"error": "CSRF token missing or invalid"}), 403
            return f(*args, **kwargs)

        # Deny all others
        return jsonify({"error": "API access denied. Please use the web interface."}), 403

    return decorated_function


# Authentication decorator for login-required routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'wallet_name' not in session:
            return jsonify({"error": "Login required"}), 401
        return f(*args, **kwargs)

    return decorated_function
