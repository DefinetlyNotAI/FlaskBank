import os
from datetime import datetime, UTC

from flask import Flask, render_template, redirect, url_for, send_from_directory, request, session
from waitress import serve
from werkzeug.security import check_password_hash

from banking.database import init_db, is_db_initialized, execute_query, execute_query_dict
from banking.decorator import api_access_control, admin_required, login_required
from banking.get_data import get_settings, get_total_currency, get_user_by_wallet_name
from banking.global_vars import DB_POOL, ALLOW_PUBLIC_API_ACCESS
from banking.log_module import create_log, rotate_logs
from banking.validate import validate_wallet_name
from api import register_unused_api_routes, register_request_api_routes, register_get_api_routes, \
    register_setup_api_routes, register_transfer_api_routes, register_admin_api_routes

# Configuration
app = Flask(__name__, static_folder='static')
SECRET = os.environ.get("SECRET_KEY", "EMPTY")
app.config["SECRET_KEY"] = SECRET
if os.environ.get("SECRET_KEY", "EMPTY") == "EMPTY":
    print("Major security issue, please set SECRET_KEY environment variable")

# Register API routes
register_unused_api_routes(app)
register_request_api_routes(app)
register_get_api_routes(app)
register_setup_api_routes(app)
register_transfer_api_routes(app)
register_admin_api_routes(app)


# Routes
@app.route('/')
def home():
    if not is_db_initialized():
        return redirect(url_for('setup_page'))

    if DB_POOL is None:
        return render_template('error.html',
                               message="Database is not initialized. Please set up the system by putting the required ENV variables.")

    settings = get_settings()
    return render_template('home.html', settings=settings, is_admin='admin' in session and session['admin'],
                           is_logged_in='wallet_name' in session)


@app.route('/setup', methods=['GET', 'POST'])
def setup_page():
    if DB_POOL is None:
        return render_template('error.html',
                               message="Please setup the required ENV variables for DB URL")

    if is_db_initialized():
        return redirect(url_for('home'))

    if request.method == 'POST':
        # Collect form data
        bank_name = request.form.get('bank_name')
        currency_name = request.form.get('currency_name')
        admin_password = request.form.get('admin_password')

        # Make a POST request to the /api/setup endpoint
        response = app.test_client().post('/api/setup', json={
            'bank_name': bank_name,
            'currency_name': currency_name,
            'admin_password': admin_password
        })

        # Check if the API call failed
        if response.status_code != 200:
            error_message = response.get_json().get('error', 'Unknown error occurred')
            return render_template('setup.html', error=error_message)

        # Redirect to home if setup is successful
        return redirect(url_for('home'))

    return render_template('setup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if not is_db_initialized():
        return redirect(url_for('setup_page'))

    if request.method == 'POST':
        wallet_name = request.form.get('wallet_name')
        password = request.form.get('password')

        # Input validation
        if not validate_wallet_name(wallet_name):
            return render_template('login.html', error="Invalid wallet name format")

        user = get_user_by_wallet_name(wallet_name)

        if user and check_password_hash(user['password'], password):
            session['wallet_name'] = wallet_name

            # Update last login time
            execute_query(
                "UPDATE users SET last_login = %s WHERE wallet_name = %s",
                (datetime.now(UTC), wallet_name),
                commit=True
            )

            if wallet_name == 'admin':
                settings = get_settings()
                if check_password_hash(settings['admin_password'], password):
                    session['admin'] = True

            create_log("Login", f"User {wallet_name} logged in", "Admin")
            return redirect(url_for('home'))

        return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')


@app.route('/logout')
def logout():
    if 'wallet_name' in session:
        create_log("Logout", f"User {session['wallet_name']} logged out", "Admin")
        session.pop('wallet_name', None)
    session.pop('admin', None)
    return redirect(url_for('home'))


# Web UI routes
@app.route('/wallet/<wallet_name>')
def wallet_page(wallet_name):
    if not validate_wallet_name(wallet_name):
        return render_template('error.html', message="Invalid wallet name format")

    user = get_user_by_wallet_name(wallet_name)

    if not user:
        return render_template('error.html', message="Wallet not found")

    settings = get_settings()
    total_used = get_total_currency()

    return render_template('wallet.html', user=user, settings=settings, total_used=total_used,
                           is_admin='admin' in session and session['admin'],
                           is_logged_in='wallet_name' in session)


@app.route('/leaderboard')
def leaderboard_page():
    settings = get_settings()

    if not settings['allow_leaderboard']:
        return render_template('error.html', message="Leaderboard is disabled")

    users = execute_query_dict(
        "SELECT wallet_name, current_currency FROM users WHERE wallet_name != 'admin' ORDER BY current_currency DESC"
    )

    return render_template('leaderboard.html', users=users, settings=settings,
                           is_admin='admin' in session and session['admin'],
                           is_logged_in='wallet_name' in session)


@app.route('/logs')
def logs_page():
    settings = get_settings()

    if not settings['allow_public_logs']:
        return render_template('error.html', message="Public logs are disabled")

    logs = execute_query_dict(
        "SELECT action, details, timestamp FROM logs WHERE private_level = 'Global' ORDER BY timestamp DESC LIMIT 50"
    )

    return render_template('logs.html', logs=logs, settings=settings,
                           is_admin='admin' in session and session['admin'],
                           is_logged_in='wallet_name' in session)


@app.route('/user/logs')
@login_required
def user_logs_page():
    wallet_name = session['wallet_name']
    logs = execute_query_dict(
        "SELECT action, details, timestamp FROM logs WHERE private_level = 'Private' AND details ILIKE %s ORDER BY timestamp DESC LIMIT 50",
        (f"%{wallet_name}%",)
    )

    settings = get_settings()

    return render_template('user_logs.html', logs=logs, settings=settings,
                           is_admin='admin' in session and session['admin'],
                           is_logged_in=True)


@app.route('/user/requests')
@login_required
def user_requests_page():
    """Page for users to view their request history"""
    wallet_name = session['wallet_name']
    requests = execute_query_dict(
        "SELECT * FROM requests WHERE wallet_name = %s ORDER BY timestamp DESC",
        (wallet_name,)
    )
    settings = get_settings()

    return render_template('user_requests.html', requests=requests, settings=settings,
                           is_admin='admin' in session and session['admin'],
                           is_logged_in=True)


@app.route('/admin/logs')
@admin_required
def admin_logs_page():
    logs = execute_query_dict(
        "SELECT action, details, timestamp FROM logs WHERE private_level = 'Admin' ORDER BY timestamp DESC LIMIT 50"
    )
    settings = get_settings()

    return render_template('admin_logs.html', logs=logs, settings=settings,
                           is_admin=True, is_logged_in=True)


@app.route('/admin/treasury')
@admin_required
def admin_treasury_page():
    settings = get_settings()
    total_used = get_total_currency()

    return render_template('treasury.html', settings=settings,
                           total_used=total_used,
                           available=settings['maximum_currency'] - total_used,
                           is_admin=True, is_logged_in=True)


@app.route('/admin/wallets')
@admin_required
def admin_wallets_page():
    users = execute_query_dict(
        "SELECT wallet_name, current_currency, is_frozen, created_at, last_login FROM users WHERE wallet_name != 'admin'"
    )
    settings = get_settings()

    return render_template('admin_wallets.html', users=users, settings=settings,
                           is_admin=True, is_logged_in=True)


@app.route('/admin/wallet/<wallet_name>')
@admin_required
def admin_wallet_detail_page(wallet_name):
    if not validate_wallet_name(wallet_name):
        return render_template('error.html', message="Invalid wallet name format")

    user = get_user_by_wallet_name(wallet_name)

    if not user:
        return render_template('error.html', message="Wallet not found")

    requests = execute_query_dict(
        "SELECT * FROM requests WHERE wallet_name = %s AND status = 'Pending'",
        (wallet_name,)
    )
    settings = get_settings()

    return render_template('admin_wallet_detail.html', user=user, requests=requests,
                           settings=settings, is_admin=True, is_logged_in=True)


@app.route('/admin/rules')
@admin_required
def admin_rules_page():
    settings = get_settings()

    return render_template('admin_rules.html', settings=settings,
                           is_admin=True, is_logged_in=True)


@app.route('/admin/requests')
@admin_required
def admin_requests_page():
    """Admin page to view all pending requests"""
    requests = execute_query_dict(
        "SELECT * FROM requests WHERE status = 'Pending' ORDER BY timestamp DESC"
    )
    settings = get_settings()

    return render_template('admin_requests.html', requests=requests, settings=settings,
                           is_admin=True, is_logged_in=True)


@app.route('/admin/sql')
@admin_required
def admin_sql_page():
    """Admin page for SQL database explorer"""
    settings = get_settings()

    return render_template('admin_sql.html', settings=settings,
                           is_admin=True, is_logged_in=True)


@app.route('/server-health')
def server_health_page():
    """Public page showing server health metrics"""
    if not is_db_initialized():
        return render_template('error.html',
                               message="The DB is not initialised so the server health page is locked from rendering")

    settings = get_settings()

    return render_template('server_health.html', settings=settings,
                           is_admin='admin' in session and session['admin'],
                           is_logged_in='wallet_name' in session)


@app.route('/requests')
@login_required
def requests_page():
    settings = get_settings()
    wallet_name = session['wallet_name']

    # Get user's pending requests
    requests = execute_query_dict(
        "SELECT * FROM requests WHERE wallet_name = %s AND status = 'Pending'",
        (wallet_name,)
    )

    return render_template('requests.html', requests=requests, settings=settings,
                           is_admin='admin' in session and session['admin'],
                           is_logged_in=True)


@app.route('/api')
def api_docs():
    if ALLOW_PUBLIC_API_ACCESS:
        return render_template('api_docs.html', is_admin='admin' in session and session['admin'],
                               is_logged_in='wallet_name' in session)
    return render_template('error.html',
                           message="API access is restricted due to security reasons (Bank decided this).")


@app.route('/about')
def about():
    if DB_POOL is None:
        return render_template('error.html', message="Database pool is not initialized")

    settings = get_settings()
    if not settings:
        return render_template('error.html', message="Database tables are not initialized")

    return render_template('about.html', settings=settings,
                           is_admin='admin' in session and session['admin'],
                           is_logged_in='wallet_name' in session)


# Serve static files
@app.route('/static/<path:filename>')
@api_access_control
@admin_required
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)


if __name__ == '__main__':
    try:
        print("Database pool is initialized, starting the server...")
        print("Checking database initialization...")
        if not init_db():
            exit("Oops! The DB init failed!! This means you have a issue with the database connection!")
        print("Rotating logs older than 30 days...")
        rotate_logs()  # Perform log rotation during startup
    except Exception as error:
        print(f"Error during startup: {error}")
        print("Database pool is not initialized. Please check your database connection.")
    finally:
        print("Starting server...")
        serve(app, host='0.0.0.0', port=5000)
