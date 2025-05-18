from functools import wraps

from flask import jsonify, session


# Authentication decorators for admin-required routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session or not session['admin']:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)

    return decorated_function


# Authentication decorator for login-required routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'wallet_name' not in session:
            return jsonify({"error": "Login required"}), 401
        return f(*args, **kwargs)

    return decorated_function
