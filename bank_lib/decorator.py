from functools import wraps
from urllib.parse import urlparse

from flask import request, jsonify, session

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
        if ALLOW_PUBLIC_API_ACCESS:
            return f(*args, **kwargs)

        # Check if the request is coming from our own site (CSRF protection)
        referer = request.headers.get('Referer', '')
        is_same_origin = referer and urlparse(referer).netloc == urlparse(request.host_url).netloc

        # Allow access if:
        # 1. User is an admin
        # 2. Request is from the same origin (our website)
        # 3. It's a GET request for public endpoints
        if ('admin' in session and session['admin']) or \
                is_same_origin or \
                (request.method == 'GET' and request.path in ['/api/get/logs', '/api/get/leaderboard',
                                                              '/api/get/currencyPool']):
            return f(*args, **kwargs)
        else:
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
