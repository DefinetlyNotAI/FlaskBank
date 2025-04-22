import os
import platform
import re
import time
import uuid
from datetime import datetime, UTC
from functools import wraps
from urllib.parse import urlparse, urljoin

import psutil
import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_from_directory
from psycopg2.pool import ThreadedConnectionPool
from waitress import serve
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import Form, StringField, PasswordField, FloatField, validators, SelectField, TextAreaField

app = Flask(__name__, static_folder='static')

# Configuration
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "EMPTY")
db_url = os.environ.get("DATABASE_URL", "EMPTY")
# Options: production or development
ENV = os.environ.get('FLASK_ENV', 'production')

# We advise to keep this FALSE as it may undermine security and put too much pressure on servers if set to True, admins bypass this
# Allow access to the endpoint if (overridden if ALLOW_PUBLIC_API_ACCESS = True):
# 1. User is an admin
# 2. Request is from the same origin (the website)
# 3. It's a GET request for public endpoints (logs, leaderboard, currency pool)
ALLOW_PUBLIC_API_ACCESS = False

# Database connection pool
db_pool = None
if db_url != "EMPTY":
    try:
        db_pool = ThreadedConnectionPool(1, 10, db_url)
        print("Database connection pool initialized successfully")
    except Exception as err:
        print(f"Error initializing database connection pool: {err}")
        db_pool = None

# Security warn
if os.environ.get("SECRET_KEY", "EMPTY") == "EMPTY":
    print("Major security issue, please set SECRET_KEY environment variable")


# TODO - remove secrets, seperate the css/js from html, check using pycharm issues, add favicon, and finally push


# Database helper functions
def get_db_connection():
    """Get a connection from the pool"""
    if db_pool is None:
        return None
    try:
        return db_pool.getconn()
    except Exception as e:
        print(f"Error getting database connection: {e}")
        return None


def release_db_connection(conn):
    """Release a connection back to the pool"""
    if db_pool is not None:
        db_pool.putconn(conn)


def execute_query(query, params=None, fetch=True, commit=False, cursor_factory=None):
    """Execute a database query with proper connection handling"""
    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            return None

        if cursor_factory:
            cur = conn.cursor(cursor_factory=cursor_factory)
        else:
            cur = conn.cursor()

        cur.execute(query, params)

        result = None
        if fetch:
            # Only fetch results for SELECT queries
            if cur.description:  # cur.description is None for non-SELECT queries
                result = cur.fetchall()

        if commit:
            conn.commit()

        cur.close()
        return result
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Database error: {e}")
        raise
    finally:
        if conn:
            release_db_connection(conn)


def execute_query_dict(query, params=None, fetch=True, commit=False):
    """Execute a query and return results as dictionaries"""
    return execute_query(query, params, fetch, commit, cursor_factory=psycopg2.extras.RealDictCursor)


# Initialize database tables
def init_db():
    """Create database tables if they don't exist"""
    if db_pool is None:
        return False

    try:
        # Settings table
        execute_query("""
                      CREATE TABLE IF NOT EXISTS settings
                      (
                          id
                          SERIAL
                          PRIMARY
                          KEY,
                          bank_name
                          VARCHAR
                      (
                          100
                      ) NOT NULL,
                          currency_name VARCHAR
                      (
                          50
                      ) NOT NULL,
                          admin_password VARCHAR
                      (
                          200
                      ) NOT NULL,
                          allow_leaderboard BOOLEAN DEFAULT TRUE,
                          allow_public_logs BOOLEAN DEFAULT TRUE,
                          allow_debts BOOLEAN DEFAULT FALSE,
                          allow_self_review BOOLEAN DEFAULT FALSE,
                          maximum_currency FLOAT DEFAULT 1000000.0
                          )
                      """, commit=True)

        # Users table
        execute_query("""
                      CREATE TABLE IF NOT EXISTS users
                      (
                          id
                          SERIAL
                          PRIMARY
                          KEY,
                          wallet_name
                          VARCHAR
                      (
                          100
                      ) UNIQUE NOT NULL,
                          password VARCHAR
                      (
                          200
                      ) NOT NULL,
                          current_currency FLOAT DEFAULT 0.0,
                          is_frozen BOOLEAN DEFAULT FALSE,
                          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                          last_login TIMESTAMP WITH TIME ZONE
                                                   )
                      """, commit=True)

        # Logs table
        execute_query("""
                      CREATE TABLE IF NOT EXISTS logs
                      (
                          id
                          SERIAL
                          PRIMARY
                          KEY,
                          action
                          VARCHAR
                      (
                          100
                      ) NOT NULL,
                          details VARCHAR
                      (
                          500
                      ) NOT NULL,
                          timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                                                  private_level VARCHAR (20) NOT NULL,
                          ip_address VARCHAR
                      (
                          45
                      )
                          )
                      """, commit=True)

        # Requests table
        execute_query("""
                      CREATE TABLE IF NOT EXISTS requests
                      (
                          id
                          SERIAL
                          PRIMARY
                          KEY,
                          request_type
                          VARCHAR
                      (
                          50
                      ) NOT NULL,
                          ticket_uuid VARCHAR
                      (
                          100
                      ) UNIQUE NOT NULL,
                          wallet_name VARCHAR
                      (
                          100
                      ) NOT NULL,
                          timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                                                  category VARCHAR (50),
                          status VARCHAR
                      (
                          20
                      ) DEFAULT 'Pending',
                          reason VARCHAR
                      (
                          500
                      ),
                          ip_address VARCHAR
                      (
                          45
                      )
                          )
                      """, commit=True)

        return True
    except Exception as e:
        print(f"Error initializing database: {e}")
        return False


# Check database connection
def check_db_connection():
    """Check if database connection is working"""
    if db_pool is None:
        return False

    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            return False

        # Try a simple query to verify connection
        cur = conn.cursor()
        cur.execute("SELECT 1")
        result = cur.fetchone()
        cur.close()

        return result is not None and result[0] == 1
    except Exception as e:
        print(f"Database connection check failed: {e}")
        return False
    finally:
        if conn:
            release_db_connection(conn)


# Form Validation Classes
class SetupForm(Form):
    bank_name = StringField('Bank Name', [
        validators.Length(min=3, max=100, message="Bank name must be between 3 and 100 characters"),
        validators.DataRequired(message="Bank name is required")
    ])
    currency_name = StringField('Currency Name', [
        validators.Length(min=1, max=50, message="Currency name must be between 1 and 50 characters"),
        validators.DataRequired(message="Currency name is required")
    ])
    admin_password = PasswordField('Admin Password', [
        validators.Length(min=8, message="Password must be at least 8 characters long"),
        validators.DataRequired(message="Admin password is required")
    ])


class WalletForm(Form):
    username = StringField('Username', [
        validators.Length(min=3, max=100, message="Username must be between 3 and 100 characters"),
        validators.DataRequired(message="Username is required"),
        validators.Regexp(r'^[a-zA-Z0-9_]+$', message="Wallet name can only contain letters, numbers, and underscores")
    ])
    password = PasswordField('Password', [
        validators.Length(min=8, message="Password must be at least 8 characters long"),
        validators.DataRequired(message="Password is required")
    ])
    initial_currency = FloatField('Initial Currency', [
        validators.NumberRange(min=0, message="Initial currency must be a non-negative number"),
        validators.Optional()
    ])

    def process(self, formdata=None, obj=None, data=None, **kwargs):
        if data and 'initial_currency' in data:
            try:
                data['initial_currency'] = float(data['initial_currency'])
            except ValueError:
                data['initial_currency'] = None
        super().process(formdata, obj, data, **kwargs)


class TransferForm(Form):
    to_wallet = StringField('To Wallet', [
        validators.Length(min=3, max=100, message="Wallet name must be between 3 and 100 characters"),
        validators.DataRequired(message="Wallet name is required"),
        validators.Regexp(r'^[a-zA-Z0-9_]+$', message="Wallet name can only contain letters, numbers, and underscores")
    ])
    amount = FloatField('Amount', [validators.DataRequired(message="Amount is required")])
    category = SelectField('Category', [validators.DataRequired(
        message="A category is required (Reward, Trade or Invoice, Penalty)")], choices=[
        ('Reward', 'Reward'),
        ('Trade', 'Trade'),
        ('Invoice', 'Invoice'),
        ('Penalty', 'Penalty')
    ])
    reason = TextAreaField('Reason', [
        validators.Length(min=2, max=500, message="Reason must be between 2 and 500 characters"),
        validators.DataRequired(message="Reason is required")
    ])


class ResetPasswordForm(Form):
    new_password = PasswordField('New Password', [
        validators.Length(min=8, message="Password must be at least 8 characters long"),
        validators.DataRequired(message="New password is required")
    ])
    reason = TextAreaField('Reason', [
        validators.Length(min=3, max=500, message="Reason must be between 3 and 500 characters"),
        validators.DataRequired(message="Reason is required"),
    ])


class RefundForm(Form):
    transfer_ticket_uuid = StringField('Transfer Ticket UUID', [
        validators.Length(min=36, max=36, message="Invalid UUID length"),
        validators.DataRequired(message="UUID is required"),
        validators.Regexp(r'^[a-f0-9-]+$', message="Invalid UUID format")
    ])
    reason = TextAreaField('Reason', [
        validators.Length(min=3, max=500, message="Reason must be between 3 and 500 characters"),
        validators.DataRequired(message="Reason is required"),
    ])


class AdminActionForm(Form):
    wallet_name = StringField('Wallet Name', [
        validators.Length(min=3, max=100, message="Wallet name must be between 3 and 100 characters"),
        validators.DataRequired(message="Wallet name is required"),
        validators.Regexp(r'^[a-zA-Z0-9_]+$', message="Wallet name can only contain letters, numbers, and underscores")
    ])
    reason = TextAreaField('Reason', [
        validators.Length(min=3, max=500, message="Reason must be between 3 and 500 characters"),
        validators.DataRequired(message="Reason is required"),
    ])


class CurrencyForm(Form):
    amount = FloatField('Amount', [
        validators.NumberRange(min=0.01, message="Amount must be greater than 0"),
        validators.DataRequired(message="Amount is required")
    ])

    def process(self, formdata=None, obj=None, data=None, **kwargs):
        if data and 'amount' in data:
            try:
                data['amount'] = float(data['amount'])
            except ValueError:
                data['amount'] = None
        super().process(formdata, obj, data, **kwargs)


class BankTransferForm(Form):
    wallet_name = StringField('Wallet Name', [
        validators.Length(min=3, max=100, message="Wallet name must be between 3 and 100 characters"),
        validators.DataRequired(message="Wallet name is required"),
        validators.Regexp(r'^[a-zA-Z0-9_]+$', message="Wallet name can only contain letters, numbers, and underscores")
    ])
    amount = FloatField('Amount', [
        validators.DataRequired(message="Amount is required")
    ])
    category = SelectField('Category', [validators.DataRequired(
        message="A category is required (Reward, Trade or Invoice, Penalty)")], choices=[
        ('Reward', 'Reward'),
        ('Trade', 'Trade'),
        ('Invoice', 'Invoice'),
        ('Penalty', 'Penalty')
    ])
    reason = TextAreaField('Reason', [
        validators.Length(min=3, max=500, message="Reason must be between 3 and 500 characters"),
        validators.DataRequired(message="Reason is required"),
    ])


class SqlQueryForm(Form):
    query = TextAreaField('SQL Query', [
        validators.DataRequired(message="Query is required")
    ])


# Security Helpers
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    else:
        return request.remote_addr


# Authentication decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session or not session['admin']:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)

    return decorated_function


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'wallet_name' not in session:
            return jsonify({"error": "Login required"}), 401
        return f(*args, **kwargs)

    return decorated_function


# Add this new decorator function after the existing decorators
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


# Helper functions
def is_db_initialized():
    """Check if the database has been initialized with settings"""
    if db_pool is None:
        return False

    try:
        result = execute_query("SELECT COUNT(*) FROM settings")
        return result and result[0][0] > 0
    except Exception as e:
        print(f"Error checking if DB is initialized: {e}")
        return False


def create_log(action, details, private_level):
    """Create a log entry in the database"""
    try:
        execute_query(
            "INSERT INTO logs (action, details, private_level, ip_address) VALUES (%s, %s, %s, %s)",
            (action, details, private_level, get_client_ip()),
            commit=True
        )
    except Exception as e:
        print(f"Error creating log: {e}")


def get_total_currency():
    """Get the total currency in circulation"""
    try:
        result = execute_query("SELECT COALESCE(SUM(current_currency), 0) FROM users WHERE wallet_name != 'admin'")
        return result[0][0] if result else 0
    except Exception as e:
        print(f"Error getting total currency: {e}")
        return 0


def validate_wallet_name(wallet_name):
    """Validate wallet name format"""
    if not wallet_name or not re.match(r'^[a-zA-Z0-9_]{3,100}$', wallet_name):
        return False
    return True


def validate_amount(amount):
    """Validate that amount is a positive number"""
    try:
        amount = float(amount)
        if amount <= 0:
            return False
        return True
    except (ValueError, TypeError):
        return False


def validate_uuid(uuid_str):
    """Validate UUID format"""
    try:
        uuid_obj = uuid.UUID(uuid_str)
        return str(uuid_obj) == uuid_str
    except (ValueError, AttributeError, TypeError):
        return False


def get_settings():
    """Get application settings"""
    try:
        settings = execute_query_dict("SELECT * FROM settings LIMIT 1")
        return settings[0] if settings else None
    except Exception as e:
        print(f"Error getting settings: {e}")
        return None


def get_user_by_wallet_name(wallet_name):
    """Get user by wallet name"""
    try:
        users = execute_query_dict(
            "SELECT * FROM users WHERE wallet_name = %s",
            (wallet_name,)
        )
        return users[0] if users else None
    except Exception as e:
        print(f"Error getting user by wallet name: {e}")
        return None


# Update admin balance to reflect available currency
def update_admin_balance():
    """Update admin balance to reflect available currency pool"""
    try:
        settings = get_settings()
        if not settings:
            return False

        total_used = get_total_currency()
        available = settings['maximum_currency'] - total_used

        # Update admin balance to reflect available currency
        execute_query(
            "UPDATE users SET current_currency = %s WHERE wallet_name = 'admin'",
            (available,),
            commit=True
        )
        return True
    except Exception as e:
        print(f"Error updating admin balance: {e}")
        return False


def get_stable_cpu_percent(duration=1.0, samples=10):
    """
    Measures CPU percent more accurately by averaging multiple samples over a duration.

    :param duration: Total time to sample over, in seconds.
    :param samples: Number of samples to take during duration.
    :return: Averaged CPU usage percentage.
    """
    interval = duration / samples
    values = []

    # Prime the measurement system (psutil needs this to reset internal deltas)
    psutil.cpu_percent(interval=None)

    for _ in range(samples):
        values.append(psutil.cpu_percent(interval=interval))

    return sum(values) / len(values)


# Get server health metrics
def get_server_health():
    """Get server health metrics"""
    try:
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=1)  # Get CPU usage with 1 second interval
        memory = psutil.virtual_memory()
        memory_percent = memory.percent

        # Disk usage
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent

        # Format uptime
        uptime_seconds = time.time() - psutil.boot_time()
        days, remainder = divmod(uptime_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        uptime_str = f"{int(days)} days, {int(hours)} hours, {int(minutes)} minutes"

        # Database metrics
        db_connected = check_db_connection()
        # Count database records
        total_users = execute_query("SELECT COUNT(*) FROM users")[0][0] if db_connected else 0
        total_requests = execute_query("SELECT COUNT(*) FROM requests")[0][0] if db_connected else 0
        total_logs = execute_query("SELECT COUNT(*) FROM logs")[0][0] if db_connected else 0

        # Additional metrics
        metrics = [
            {
                "name": "System Uptime",
                "value": uptime_str,
                "status": "good"
            },
            {
                "name": "Python Version",
                "value": platform.python_version(),
                "status": "good"
            },
            {
                "name": "Database Connection Pool",
                "value": f"Min: {db_pool.minconn}, Max: {db_pool.maxconn}" if db_pool else "Not available",
                "status": "good" if db_pool else "critical"
            },
            {
                "name": "Memory Usage",
                "value": f"{memory.used / (1024 * 1024):.2f} MB / {memory.total / (1024 * 1024):.2f} MB",
                "status": "good" if memory_percent < 70 else "warning" if memory_percent < 90 else "critical"
            },
            {
                "name": "Disk Space",
                "value": f"{disk.used / (1024 * 1024 * 1024):.2f} GB / {disk.total / (1024 * 1024 * 1024):.2f} GB",
                "status": "good" if disk_percent < 80 else "warning" if disk_percent < 95 else "critical"
            }
        ]

        return {
            "system": {
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "disk_percent": disk_percent
            },
            "database": {
                "connected": db_connected,
                "total_users": total_users,
                "total_requests": total_requests,
                "total_logs": total_logs
            },
            "metrics": metrics
        }
    except Exception as e:
        print(f"Error getting server health: {e}")
        return {
            "system": {
                "cpu_percent": 0,
                "memory_percent": 0,
                "disk_percent": 0
            },
            "database": {
                "connected": False,
                "total_users": 0,
                "total_requests": 0,
                "total_logs": 0
            },
            "metrics": [
                {
                    "name": "Error",
                    "value": str(e),
                    "status": "critical"
                }
            ]
        }


# Routes
@app.route('/')
def home():
    if not is_db_initialized():
        return redirect(url_for('setup_page'))

    if db_pool is None:
        return render_template('error.html',
                               message="Database is not initialized. Please set up the system by putting the required ENV variables.")

    settings = get_settings()
    return render_template('home.html', settings=settings, is_admin='admin' in session and session['admin'],
                           is_logged_in='wallet_name' in session)


@app.route('/setup', methods=['GET', 'POST'])
def setup_page():
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

            # Redirect to a safe URL
            next_page = request.args.get('next')
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
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


# API Routes for database checks and initialization
@app.route('/api/check-database', methods=['GET'])
@api_access_control
def api_check_database():
    """API endpoint to check database connection"""
    if check_db_connection():
        return jsonify({"status": "success", "message": "Database connection successful"})
    else:
        return jsonify({"status": "error",
                        "message": "Database connection failed. Please check your database configuration."}), 500


@app.route('/api/init-database', methods=['POST'])
@api_access_control
@admin_required
def api_init_database():
    """API endpoint to initialize database tables"""
    if init_db():
        return jsonify({"status": "success", "message": "Database tables created successfully"})
    else:
        return jsonify({"status": "error",
                        "message": "Failed to create database tables. Please check your database configuration."}), 500


@app.route('/api/setup', methods=['POST'])
@api_access_control
def api_setup():
    if is_db_initialized():
        return jsonify({"error": "Bank already initialized"}), 400

    data = request.json
    form = SetupForm(data=data)

    if not form.validate():
        errors = {field: errors[0] for field, errors in form.errors.items()}
        return jsonify({"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

    bank_name = data.get('bank_name')
    currency_name = data.get('currency_name')
    admin_password = data.get('admin_password')

    try:
        # Insert settings
        execute_query(
            "INSERT INTO settings (bank_name, currency_name, admin_password) VALUES (%s, %s, %s)",
            (bank_name, currency_name, generate_password_hash(admin_password)),
            commit=True
        )

        # Create admin user
        execute_query(
            "INSERT INTO users (wallet_name, password, current_currency) VALUES (%s, %s, %s)",
            ("admin", generate_password_hash(admin_password), 1000000),  # Admin starts with all currency
            commit=True
        )

        create_log("Setup", "Bank system initialized", "Admin")
        create_log("Bank Created", f"Bank {bank_name} has been created with {currency_name} as currency", "Global")

        return jsonify({"message": "Bank system initialized successfully"})
    except Exception as e:
        print(f"Error during setup: {e}")
        return jsonify({"error": f"Setup failed: {str(e)}"}), 500


@app.route('/api/setup/wallet', methods=['POST'])
@api_access_control
@admin_required
def api_setup_wallet():
    data = request.json
    form = WalletForm(data=data)

    if not form.validate():
        errors = {field: errors[0] for field, errors in form.errors.items()}
        return jsonify({"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

    username = data.get('username')
    password = data.get('password')
    initial_currency = float(data.get('initial_currency', 0))

    # Check if wallet already exists
    existing_wallet = get_user_by_wallet_name(username)
    if existing_wallet:
        return jsonify({"error": "Wallet already exists"}), 400

    settings = get_settings()
    total_currency = get_total_currency()

    if total_currency + initial_currency > settings['maximum_currency']:
        return jsonify({"error": "Exceeds maximum currency limit"}), 400

    try:
        # Create user
        execute_query(
            "INSERT INTO users (wallet_name, password, current_currency) VALUES (%s, %s, %s)",
            (username, generate_password_hash(password), initial_currency),
            commit=True
        )

        # Update admin balance
        update_admin_balance()

        create_log("Wallet Creation",
                   f"Admin created wallet for {username} with {initial_currency} {settings['currency_name']}", "Admin")

        # Add public log for wallet creation
        create_log("New Wallet",
                   f"User {username} joined the bank with {initial_currency} {settings['currency_name']}", "Global")

        return jsonify({"message": f"Wallet created for {username}"})
    except Exception as e:
        print(f"Error creating wallet: {e}")
        return jsonify({"error": f"Failed to create wallet: {str(e)}"}), 500


@app.route('/api/setup/rules', methods=['POST'])
@api_access_control
@admin_required
def api_setup_rules():
    data = request.json

    # Build update query dynamically based on provided fields
    update_fields = []
    params = []

    if 'allow_leaderboard' in data:
        update_fields.append("allow_leaderboard = %s")
        params.append(bool(data['allow_leaderboard']))

    if 'allow_public_logs' in data:
        update_fields.append("allow_public_logs = %s")
        params.append(bool(data['allow_public_logs']))

    if 'allow_debts' in data:
        update_fields.append("allow_debts = %s")
        params.append(bool(data['allow_debts']))

    if 'allow_self_review' in data:
        update_fields.append("allow_self_review = %s")
        params.append(bool(data['allow_self_review']))

    if update_fields:
        try:
            query = f"UPDATE settings SET {', '.join(update_fields)}"
            execute_query(query, params, commit=True)

            create_log("Rules Update", "Admin updated bank rules", "Admin")
            create_log("Bank Rules Changed", "The bank's rules have been updated by an administrator", "Global")

            return jsonify({"message": "Rules updated successfully"})
        except Exception as e:
            print(f"Error updating rules: {e}")
            return jsonify({"error": f"Failed to update rules: {str(e)}"}), 500
    else:
        return jsonify({"error": "No rules provided for update"}), 400


@app.route('/api/get/wallet', methods=['GET'])
@api_access_control
def api_get_wallet():
    wallet_name = request.args.get('wallet_name')

    if not validate_wallet_name(wallet_name):
        return jsonify({"error": "Invalid wallet name format"}), 400

    # Get user
    user = get_user_by_wallet_name(wallet_name)

    if not user:
        return jsonify({"error": "Wallet not found"}), 404

    settings = get_settings()

    return jsonify({
        "wallet_name": user['wallet_name'],
        "balance": user['current_currency'],
        "currency": settings['currency_name'],
        "is_frozen": user['is_frozen']
    })


@app.route('/api/get/leaderboard', methods=['GET'])
@api_access_control
def api_get_leaderboard():
    settings = get_settings()

    if not settings['allow_leaderboard']:
        return jsonify({"error": "Leaderboard is disabled"}), 403

    try:
        limit = int(request.args.get('limit', 10))
        if limit < 1 or limit > 100:  # Reasonable limits
            limit = 10
    except ValueError:
        limit = 10

    # Get leaderboard
    users = execute_query_dict(
        "SELECT wallet_name, current_currency FROM users WHERE wallet_name != 'admin' ORDER BY current_currency DESC LIMIT %s",
        (limit,)
    )

    leaderboard = [{
        "wallet_name": user['wallet_name'],
        "balance": user['current_currency'],
        "currency": settings['currency_name']
    } for user in users]

    return jsonify(leaderboard)


@app.route('/api/get/logs', methods=['GET'])
@api_access_control
def api_get_logs():
    settings = get_settings()

    if not settings['allow_public_logs']:
        return jsonify({"error": "Public logs are disabled"}), 403

    try:
        limit = int(request.args.get('limit', 50))
        if limit < 1 or limit > 500:  # Reasonable limits
            limit = 50
    except ValueError:
        limit = 50

    # Get logs
    logs = execute_query_dict(
        "SELECT action, details, timestamp FROM logs WHERE private_level = 'Global' ORDER BY timestamp DESC LIMIT %s",
        (limit,)
    )

    log_list = [{
        "action": log['action'],
        "details": log['details'],
        "timestamp": log['timestamp'].isoformat()
    } for log in logs]

    return jsonify(log_list)


@app.route('/api/get/wallet/logs', methods=['GET'])
@api_access_control
@login_required
def api_get_wallet_logs():
    try:
        limit = int(request.args.get('limit', 50))
        if limit < 1 or limit > 500:  # Reasonable limits
            limit = 50
    except ValueError:
        limit = 50

    wallet_name = session['wallet_name']

    # Get logs
    logs = execute_query_dict(
        "SELECT id, action, details, timestamp FROM logs WHERE private_level = 'Private' AND details ILIKE %s ORDER BY timestamp DESC LIMIT %s",
        (f"%{wallet_name}%", limit)
    )

    log_list = [{
        "id": log['id'],
        "action": log['action'],
        "details": log['details'],
        "timestamp": log['timestamp'].isoformat()
    } for log in logs]

    return jsonify(log_list)


@app.route('/api/get/user/requests', methods=['GET'])
@api_access_control
@login_required
def api_get_user_requests():
    """Get requests for the current user"""
    try:
        limit = int(request.args.get('limit', 50))
        if limit < 1 or limit > 500:  # Reasonable limits
            limit = 50
    except ValueError:
        limit = 50

    wallet_name = session['wallet_name']

    # Get requests
    requests = execute_query_dict(
        "SELECT * FROM requests WHERE wallet_name = %s ORDER BY timestamp DESC LIMIT %s",
        (wallet_name, limit)
    )

    request_list = [{
        "request_type": req['request_type'],
        "ticket_uuid": req['ticket_uuid'],
        "category": req['category'],
        "status": req['status'],
        "reason": req['reason'],
        "timestamp": req['timestamp'].isoformat() if req['timestamp'] else None
    } for req in requests]

    return jsonify(request_list)


@app.route('/api/get/admin/logs', methods=['GET'])
@api_access_control
@admin_required
def api_get_admin_logs():
    try:
        limit = int(request.args.get('limit', 50))
        if limit < 1 or limit > 500:  # Reasonable limits
            limit = 50
    except ValueError:
        limit = 50

    # Get logs
    logs = execute_query_dict(
        "SELECT action, details, timestamp FROM logs WHERE private_level = 'Admin' ORDER BY timestamp DESC LIMIT %s",
        (limit,)
    )

    log_list = [{
        "action": log['action'],
        "details": log['details'],
        "timestamp": log['timestamp'].isoformat()
    } for log in logs]

    return jsonify(log_list)


@app.route('/api/get/currencyPool', methods=['GET'])
@api_access_control
def api_get_currency_pool():
    settings = get_settings()
    total_used = get_total_currency()

    return jsonify({
        "total_used_currency": total_used,
        "maximum_currency": settings['maximum_currency'],
        "available_currency": settings['maximum_currency'] - total_used,
        "currency_name": settings['currency_name']
    })


@app.route('/api/get/walletList', methods=['GET'])
@api_access_control
@admin_required
def api_get_wallet_list():
    # Get users
    users = execute_query_dict(
        "SELECT wallet_name, current_currency, is_frozen, created_at, last_login FROM users WHERE wallet_name != 'admin'"
    )

    settings = get_settings()

    wallet_list = [{
        "wallet_name": user['wallet_name'],
        "balance": user['current_currency'],
        "currency": settings['currency_name'],
        "is_frozen": user['is_frozen'],
        "created_at": user['created_at'].isoformat() if user['created_at'] else None,
        "last_login": user['last_login'].isoformat() if user['last_login'] else None
    } for user in users]

    return jsonify(wallet_list)


@app.route('/api/get/requests', methods=['GET'])
@api_access_control
@admin_required
def api_get_all_requests():
    """Get all pending requests for admin"""
    try:
        limit = int(request.args.get('limit', 50))
        if limit < 1 or limit > 500:  # Reasonable limits
            limit = 50
    except ValueError:
        limit = 50

    # Get all pending requests
    requests = execute_query_dict(
        "SELECT * FROM requests WHERE status = 'Pending' ORDER BY timestamp DESC LIMIT %s",
        (limit,)
    )

    request_list = [{
        "request_type": req['request_type'],
        "ticket_uuid": req['ticket_uuid'],
        "wallet_name": req['wallet_name'],
        "timestamp": req['timestamp'].isoformat() if req['timestamp'] else None,
        "category": req['category'],
        "status": req['status'],
        "reason": req['reason']
    } for req in requests]

    return jsonify(request_list)


@app.route('/api/server/health', methods=['GET'])
@api_access_control
def api_server_health():
    """Get server health metrics"""
    return jsonify(get_server_health())


@app.route('/api/admin/sql', methods=['POST'])
@api_access_control
@admin_required
def api_admin_sql():
    """Execute SQL query"""
    data = request.json
    form = SqlQueryForm(data=data)

    if not form.validate():
        errors = {field: errors[0] for field, errors in form.errors.items()}
        return jsonify({"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

    query = data.get('query')

    # Basic security check - prevent destructive operations
    if re.search(r'\b(DROP|TRUNCATE|DELETE)\b', query, re.IGNORECASE) and not re.search(r'\bWHERE\b', query,
                                                                                        re.IGNORECASE):
        return jsonify({"error": "Destructive operations without WHERE clause are not allowed"}), 400

    try:
        # Execute query
        if query.strip().upper().startswith(('SELECT', 'SHOW', 'DESCRIBE', 'EXPLAIN')):
            results = execute_query_dict(query)
            return jsonify({"results": results})
        else:
            execute_query(query, commit=True)
            return jsonify({"results": [], "message": "Query executed successfully"})
    except Exception as e:
        print(f"Error executing SQL query: {e}")
        return jsonify({"error": f"Query failed: {str(e)}"}), 500


@app.route('/api/admin/delete-record', methods=['POST'])
@api_access_control
@admin_required
def api_admin_delete_record():
    """Delete a record from a table"""
    data = request.json
    table = data.get('table')
    field = data.get('field')
    value = data.get('value')

    if not table or not field or not value:
        return jsonify({"error": "Missing required parameters"}), 400

    # Validate table name
    if table not in ['users', 'requests', 'logs']:
        return jsonify({"error": "Invalid table name"}), 400

    # Prevent deleting admin user
    if (table == 'users' and field == 'wallet_name' and value == 'admin') or \
            (table == 'users' and field == 'id' and get_user_by_wallet_name('admin')['id'] == int(value)):
        return jsonify({"error": "Cannot delete admin user"}), 400

    try:
        # Delete record
        execute_query(
            f"DELETE FROM {table} WHERE {field} = %s",
            (value,),
            commit=True
        )

        # Log the action
        create_log("Record Deleted", f"Admin deleted record from {table} where {field} = {value}", "Admin")

        return jsonify({"message": f"Record deleted successfully from {table}"})
    except Exception as e:
        print(f"Error deleting record: {e}")
        return jsonify({"error": f"Failed to delete record: {str(e)}"}), 500


@app.route('/api/transfer/toWallet', methods=['POST'])
@api_access_control
@login_required
def api_transfer_to_wallet():
    data = request.json
    form = TransferForm(data=data)

    if not form.validate():
        errors = {field: errors[0] for field, errors in form.errors.items()}
        return jsonify({"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

    from_wallet = session['wallet_name']
    to_wallet = data.get('to_wallet')
    category = data.get('category')
    reason = data.get('reason')
    amount = float(data.get('amount', 0))

    # Additional validation
    if from_wallet == to_wallet:
        return jsonify({"error": "Cannot transfer to your own wallet"}), 400

    # Get users
    from_user = get_user_by_wallet_name(from_wallet)
    to_user = get_user_by_wallet_name(to_wallet)

    if not to_user:
        return jsonify({"error": "Recipient wallet not found"}), 404

    if from_user['is_frozen']:
        return jsonify({"error": "Your wallet is frozen"}), 403

    if to_user['is_frozen']:
        return jsonify({"error": "Recipient wallet is frozen"}), 403

    settings = get_settings()

    if from_user['current_currency'] < amount and not settings['allow_debts']:
        return jsonify({"error": "Insufficient funds and debts are not allowed"}), 400

    # For Penalty or Invoice categories, create a request instead of direct transfer
    if category in ["Penalty", "Invoice"]:
        try:
            ticket_uuid = str(uuid.uuid4())

            # Create request record
            execute_query(
                """
                INSERT INTO requests
                (request_type, ticket_uuid, wallet_name, category, status, reason, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                ("Transfer", ticket_uuid, from_wallet, category, "Pending", reason, get_client_ip()),
                commit=True
            )

            create_log("Transfer Request",
                       f"{from_wallet} requested a transfer of {amount} {settings['currency_name']} to {to_wallet} for {category}: {reason}",
                       "Private")

            return jsonify({
                "message": "Transfer request submitted for approval",
                "transfer_ticket_uuid": ticket_uuid
            })
        except Exception as e:
            print(f"Error creating transfer request: {e}")
            return jsonify({"error": f"Transfer request failed: {str(e)}"}), 500
    else:
        try:
            # Update balances
            execute_query(
                "UPDATE users SET current_currency = current_currency - %s WHERE wallet_name = %s",
                (amount, from_wallet),
                commit=True
            )

            execute_query(
                "UPDATE users SET current_currency = current_currency + %s WHERE wallet_name = %s",
                (amount, to_wallet),
                commit=True
            )

            # Update admin balance
            update_admin_balance()

            ticket_uuid = str(uuid.uuid4())

            # Create request record
            execute_query(
                """
                INSERT INTO requests
                (request_type, ticket_uuid, wallet_name, category, status, reason, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                ("Transfer", ticket_uuid, from_wallet, category, "Complete", reason, get_client_ip()),
                commit=True
            )

            create_log("Transfer",
                       f"{from_wallet} transferred {amount} {settings['currency_name']} to {to_wallet} for {category}: {reason} (transfer ticket uuid: {ticket_uuid})",
                       "Private")

            # Add public log for large transfers
            if amount >= 100:
                create_log("Large Transfer",
                           f"User {from_wallet} transferred {amount} {settings['currency_name']} to {to_wallet}",
                           "Global")

            return jsonify({
                "message": "Transfer completed successfully",
                "transfer_ticket_uuid": ticket_uuid
            })
        except Exception as e:
            print(f"Error during transfer: {e}")
            return jsonify({"error": f"Transfer failed: {str(e)}"}), 500


@app.route('/api/transfer/bank', methods=['POST'])
@api_access_control
@admin_required
def api_transfer_bank():
    data = request.json
    form = BankTransferForm(data=data)

    if not form.validate():
        errors = {field: errors[0] for field, errors in form.errors.items()}
        return jsonify({"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

    wallet_name = data.get('wallet_name')
    category = data.get('category')
    reason = data.get('reason')
    amount = float(data.get('amount', 0))

    # Get user
    user = get_user_by_wallet_name(wallet_name)

    if not user:
        return jsonify({"error": "Wallet not found"}), 404

    if user['is_frozen']:
        return jsonify({"error": "Wallet is frozen"}), 403

    settings = get_settings()
    total_currency = get_total_currency()

    if amount > 0 and total_currency + amount > settings['maximum_currency']:
        return jsonify({"error": "Exceeds maximum currency limit"}), 400

    try:
        # Update balance
        execute_query(
            "UPDATE users SET current_currency = current_currency + %s WHERE wallet_name = %s",
            (amount, wallet_name),
            commit=True
        )

        # Update admin balance
        update_admin_balance()

        ticket_uuid = str(uuid.uuid4())

        # Create request record
        execute_query(
            """
            INSERT INTO requests
            (request_type, ticket_uuid, wallet_name, category, status, reason, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            ("BankTransfer", ticket_uuid, wallet_name, category, "Complete", reason, get_client_ip()),
            commit=True
        )

        action = "Deposit" if amount > 0 else "Withdrawal"
        create_log(action,
                   f"Admin {action.lower()}ed {abs(amount)} {settings['currency_name']} to {wallet_name} for {category}: {reason}",
                   "Admin")

        # Add public log for bank transfers
        create_log("Bank Transfer",
                   f"Bank {action.lower()}ed {abs(amount)} {settings['currency_name']} to {wallet_name}",
                   "Global")

        return jsonify({
            "message": f"{action} completed successfully",
            "transfer_ticket_uuid": ticket_uuid
        })
    except Exception as e:
        print(f"Error during bank transfer: {e}")
        return jsonify({"error": f"Bank transfer failed: {str(e)}"}), 500


@app.route('/api/request/refund', methods=['POST'])
@api_access_control
@login_required
def api_request_refund():
    data = request.json

    # Extract log ID from the request
    log_id = data.get('log_id')
    reason = data.get('reason')

    if not log_id:
        return jsonify({"error": "Log ID is required"}), 400

    if not reason:
        return jsonify({"error": "Reason is required"}), 400

    # Get the log entry
    log = execute_query_dict(
        "SELECT * FROM logs WHERE id = %s",
        (log_id,)
    )

    if not log:
        return jsonify({"error": "Log not found"}), 404

    log = log[0]

    # Check if this is a transfer log
    if log['action'] != "Transfer":
        return jsonify({"error": "Can only request refund for transfers"}), 400

    wallet_name = session['wallet_name']

    # Check if this is the user's own transfer
    if wallet_name not in log['details']:
        return jsonify({"error": "You can only request refunds for your own transfers"}), 403

    try:
        refund_uuid = str(uuid.uuid4())

        # Create refund request
        execute_query(
            """
            INSERT INTO requests
            (request_type, ticket_uuid, wallet_name, category, status, reason, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            ("Refund", refund_uuid, wallet_name, "Refund", "Pending", f"Refund for log ID {log_id}: {reason}",
             get_client_ip()),
            commit=True
        )

        create_log("Refund Request",
                   f"{wallet_name} requested refund for log ID {log_id}: {reason}",
                   "Admin")

        return jsonify({
            "message": "Refund request submitted",
            "request_ticket_uuid": refund_uuid
        })
    except Exception as e:
        print(f"Error requesting refund: {e}")
        return jsonify({"error": f"Refund request failed: {str(e)}"}), 500


@app.route('/api/request/resetPassword', methods=['POST'])
@api_access_control
@login_required
def api_request_reset_password():
    data = request.json
    form = ResetPasswordForm(data=data)

    if not form.validate():
        errors = {field: errors[0] for field, errors in form.errors.items()}
        return jsonify({"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

    reason = data.get('reason')
    new_password = data.get('new_password')

    wallet_name = session['wallet_name']
    settings = get_settings()

    try:
        if settings['allow_self_review']:
            # Update password directly
            execute_query(
                "UPDATE users SET password = %s WHERE wallet_name = %s",
                (generate_password_hash(new_password), wallet_name),
                commit=True
            )

            create_log("Password Reset",
                       f"{wallet_name} reset their password",
                       "Admin")

            return jsonify({
                "message": "Password reset successfully"
            })
        else:
            # Create password reset request
            reset_uuid = str(uuid.uuid4())

            execute_query(
                """
                INSERT INTO requests
                    (request_type, ticket_uuid, wallet_name, status, reason, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                ("PasswordReset", reset_uuid, wallet_name, "Pending", reason, get_client_ip()),
                commit=True
            )

            create_log("Password Reset Request",
                       f"{wallet_name} requested password reset: {reason}",
                       "Admin")

            return jsonify({
                "message": "Password reset request submitted",
                "request_ticket_uuid": reset_uuid
            })
    except Exception as e:
        print(f"Error resetting password: {e}")
        return jsonify({"error": f"Password reset failed: {str(e)}"}), 500


@app.route('/api/admin/burnWallet', methods=['POST'])
@api_access_control
@admin_required
def api_admin_burn_wallet():
    data = request.json
    form = AdminActionForm(data=data)

    if not form.validate():
        errors = {field: errors[0] for field, errors in form.errors.items()}
        return jsonify({"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

    wallet_name = data.get('wallet_name')
    reason = data.get('reason')

    # Get user
    user = get_user_by_wallet_name(wallet_name)

    if not user:
        return jsonify({"error": "Wallet not found"}), 404

    if wallet_name == 'admin':
        return jsonify({"error": "Cannot burn admin wallet"}), 403

    try:
        # Delete user
        execute_query(
            "DELETE FROM users WHERE wallet_name = %s",
            (wallet_name,),
            commit=True
        )

        # Update admin balance
        update_admin_balance()

        create_log("Wallet Burned",
                   f"Admin burned wallet {wallet_name}: {reason}",
                   "Admin")

        # Add public log for wallet deletion
        create_log("Wallet Removed",
                   f"User {wallet_name}'s wallet has been removed from the bank",
                   "Global")

        return jsonify({
            "message": f"Wallet {wallet_name} burned successfully"
        })
    except Exception as e:
        print(f"Error burning wallet: {e}")
        return jsonify({"error": f"Failed to burn wallet: {str(e)}"}), 500


@app.route('/api/admin/freezeWallet', methods=['POST'])
@api_access_control
@admin_required
def api_admin_freeze_wallet():
    data = request.json
    form = AdminActionForm(data=data)

    if not form.validate():
        errors = {field: errors[0] for field, errors in form.errors.items()}
        return jsonify({"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

    wallet_name = data.get('wallet_name')
    reason = data.get('reason')

    # Get user
    user = get_user_by_wallet_name(wallet_name)

    if not user:
        return jsonify({"error": "Wallet not found"}), 404

    if wallet_name == 'admin':
        return jsonify({"error": "Cannot freeze admin wallet"}), 403

    try:
        # Freeze wallet
        execute_query(
            "UPDATE users SET is_frozen = TRUE WHERE wallet_name = %s",
            (wallet_name,),
            commit=True
        )

        create_log("Wallet Frozen",
                   f"Admin froze wallet {wallet_name}: {reason}",
                   "Admin")

        # Add public log for wallet freeze
        create_log("Wallet Frozen",
                   f"User {wallet_name}'s wallet has been frozen",
                   "Global")

        return jsonify({
            "message": f"Wallet {wallet_name} frozen successfully"
        })
    except Exception as e:
        print(f"Error freezing wallet: {e}")
        return jsonify({"error": f"Failed to freeze wallet: {str(e)}"}), 500


@app.route('/api/admin/unfreezeWallet', methods=['POST'])
@api_access_control
@admin_required
def api_admin_unfreeze_wallet():
    data = request.json
    form = AdminActionForm(data=data)

    if not form.validate():
        errors = {field: errors[0] for field, errors in form.errors.items()}
        return jsonify({"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

    wallet_name = data.get('wallet_name')
    reason = data.get('reason')

    # Get user
    user = get_user_by_wallet_name(wallet_name)

    if not user:
        return jsonify({"error": "Wallet not found"}), 404

    try:
        # Unfreeze wallet
        execute_query(
            "UPDATE users SET is_frozen = FALSE WHERE wallet_name = %s",
            (wallet_name,),
            commit=True
        )

        create_log("Wallet Unfrozen",
                   f"Admin unfroze wallet {wallet_name}: {reason}",
                   "Admin")

        # Add public log for wallet unfreeze
        create_log("Wallet Unfrozen",
                   f"User {wallet_name}'s wallet has been unfrozen",
                   "Global")

        return jsonify({
            "message": f"Wallet {wallet_name} unfrozen successfully"
        })
    except Exception as e:
        print(f"Error unfreezing wallet: {e}")
        return jsonify({"error": f"Failed to unfreeze wallet: {str(e)}"}), 500


@app.route('/api/admin/resetWallet', methods=['POST'])
@api_access_control
@admin_required
def api_admin_reset_wallet():
    data = request.json
    form = AdminActionForm(data=data)

    if not form.validate():
        errors = {field: errors[0] for field, errors in form.errors.items()}
        return jsonify({"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

    wallet_name = data.get('wallet_name')
    reason = data.get('reason')

    # Get user
    user = get_user_by_wallet_name(wallet_name)

    if not user:
        return jsonify({"error": "Wallet not found"}), 404

    if wallet_name == 'admin':
        return jsonify({"error": "Cannot reset admin wallet"}), 403

    try:
        # Reset wallet balance
        execute_query(
            "UPDATE users SET current_currency = 0 WHERE wallet_name = %s",
            (wallet_name,),
            commit=True
        )

        # Update admin balance
        update_admin_balance()

        # Delete related logs
        execute_query(
            "DELETE FROM logs WHERE private_level = 'Private' AND details ILIKE %s",
            (f"%{wallet_name}%",),
            commit=True
        )

        create_log("Wallet Reset",
                   f"Admin reset wallet {wallet_name}: {reason}",
                   "Admin")

        # Add public log for wallet reset
        create_log("Wallet Reset",
                   f"User {wallet_name}'s wallet has been reset to 0",
                   "Global")

        return jsonify({
            "message": f"Wallet {wallet_name} reset successfully"
        })
    except Exception as e:
        print(f"Error resetting wallet: {e}")
        return jsonify({"error": f"Failed to reset wallet: {str(e)}"}), 500


@app.route('/api/admin/approveRequest', methods=['POST'])
@api_access_control
@admin_required
def api_admin_approve_request():
    data = request.json
    request_uuid = data.get('request_ticket_uuid')

    if not request_uuid or not validate_uuid(request_uuid):
        return jsonify({"error": "Invalid request ticket UUID"}), 400

    try:
        # Get request
        request_item = execute_query_dict(
            "SELECT * FROM requests WHERE ticket_uuid = %s",
            (request_uuid,)
        )

        if not request_item:
            return jsonify({"error": "Request not found"}), 404

        request_item = request_item[0]

        if request_item['status'] != "Pending":
            return jsonify({"error": "Request is not pending"}), 400

        # Update request status
        execute_query(
            "UPDATE requests SET status = 'Approved' WHERE ticket_uuid = %s",
            (request_uuid,),
            commit=True
        )

        settings = get_settings()

        # Handle specific request types
        if request_item['request_type'] == "Refund":
            # Process refund logic
            # Extract log ID from reason (e.g., "Refund for log ID 123: reason text")
            log_id_match = re.search(r'log ID (\d+):', request_item['reason'])
            if log_id_match:
                log_id = int(log_id_match.group(1))

                # Get the original transfer log
                transfer_log = execute_query_dict(
                    "SELECT * FROM logs WHERE id = %s AND action = 'Transfer'",
                    (log_id,)
                )

                if transfer_log:
                    transfer_log = transfer_log[0]

                    # Parse the transfer details to extract sender, recipient, and amount
                    # Example: "user1 transferred 50 Credits to user2 for Trade: reason"
                    transfer_details = transfer_log['details']
                    sender_match = re.match(r'([a-zA-Z0-9_]+) transferred', transfer_details)
                    recipient_match = re.search(r'to ([a-zA-Z0-9_]+) for', transfer_details)
                    amount_match = re.search(r'transferred ([0-9.]+)', transfer_details)

                    if sender_match and recipient_match and amount_match:
                        sender = sender_match.group(1)
                        recipient = recipient_match.group(1)
                        amount = float(amount_match.group(1))

                        # Verify the refund requester is the sender
                        if sender == request_item['wallet_name']:
                            # Get users
                            sender_user = get_user_by_wallet_name(sender)
                            recipient_user = get_user_by_wallet_name(recipient)

                            if sender_user and recipient_user:
                                # Check if recipient has enough funds
                                if recipient_user['current_currency'] >= amount or settings['allow_debts']:
                                    # Reverse the transaction
                                    execute_query(
                                        "UPDATE users SET current_currency = current_currency + %s WHERE wallet_name = %s",
                                        (amount, sender),
                                        commit=True
                                    )

                                    execute_query(
                                        "UPDATE users SET current_currency = current_currency - %s WHERE wallet_name = %s",
                                        (amount, recipient),
                                        commit=True
                                    )

                                    # Update admin balance
                                    update_admin_balance()

                                    # Create log for the refund
                                    create_log("Refund",
                                               f"Admin approved refund of {amount} {settings['currency_name']} from {recipient} to {sender}",
                                               "Admin")

                                    create_log("Refund",
                                               f"{amount} {settings['currency_name']} refunded from {recipient} to {sender}",
                                               "Private")

                                    # Add public log for large refunds
                                    if amount >= 100:
                                        create_log("Large Refund",
                                                   f"{amount} {settings['currency_name']} refunded from {recipient} to {sender}",
                                                   "Global")
                                else:
                                    # If recipient doesn't have enough funds, mark as approved but note the issue
                                    create_log("Refund Failed",
                                               f"Refund of {amount} {settings['currency_name']} from {recipient} to {sender} failed: Insufficient funds",
                                               "Admin")
                                    return jsonify(
                                        {"error": f"Recipient {recipient} has insufficient funds for refund"}), 400
                        else:
                            create_log("Refund Error",
                                       f"Refund request from {request_item['wallet_name']} doesn't match original sender {sender}",
                                       "Admin")
                            return jsonify({"error": "Refund requester doesn't match original sender"}), 400

        elif request_item['request_type'] == "PasswordReset":
            # Process password reset logic here
            user = get_user_by_wallet_name(request_item['wallet_name'])
            if user:
                # Generate a temporary password
                temp_password = str(uuid.uuid4())[:8]

                # Update password
                execute_query(
                    "UPDATE users SET password = %s WHERE wallet_name = %s",
                    (generate_password_hash(temp_password), request_item['wallet_name']),
                    commit=True
                )

                # Update request reason with temp password
                execute_query(
                    "UPDATE requests SET reason = reason || ' | Temporary password: ' || %s WHERE ticket_uuid = %s",
                    (temp_password, request_uuid),
                    commit=True
                )
        elif request_item['request_type'] == "Transfer" and request_item['category'] in ["Penalty", "Invoice"]:
            # Process transfer request
            wallet_name = request_item['wallet_name']
            details = request_item['reason']

            # Parse amount from details (this would need to be improved in a real system)
            amount_match = re.search(r'(\d+(\.\d+)?)', details)
            if amount_match:
                amount = float(amount_match.group(1))

                # Get user
                user = get_user_by_wallet_name(wallet_name)
                if user:
                    # Update balance
                    execute_query(
                        "UPDATE users SET current_currency = current_currency - %s WHERE wallet_name = %s",
                        (amount, wallet_name),
                        commit=True
                    )

                    # Update admin balance
                    update_admin_balance()

                    create_log("Transfer Approved",
                               f"Admin approved transfer request from {wallet_name} for {amount} {get_settings()['currency_name']}",
                               "Admin")

        create_log("Request Approved",
                   f"Admin approved request {request_uuid} for {request_item['wallet_name']}",
                   "Admin")

        # Add public log for request approval
        create_log("Request Approved",
                   f"A request from user {request_item['wallet_name']} has been approved",
                   "Global")

        return jsonify({
            "message": f"Request {request_uuid} approved successfully"
        })
    except Exception as e:
        print(f"Error approving request: {e}")
        return jsonify({"error": f"Failed to approve request: {str(e)}"}), 500


@app.route('/api/admin/rejectRequest', methods=['POST'])
@api_access_control
@admin_required
def api_admin_reject_request():
    data = request.json
    request_uuid = data.get('request_ticket_uuid')

    if not request_uuid or not validate_uuid(request_uuid):
        return jsonify({"error": "Invalid request ticket UUID"}), 400

    try:
        # Get request
        request_item = execute_query_dict(
            "SELECT * FROM requests WHERE ticket_uuid = %s",
            (request_uuid,)
        )

        if not request_item:
            return jsonify({"error": "Request not found"}), 404

        request_item = request_item[0]

        if request_item['status'] != "Pending":
            return jsonify({"error": "Request is not pending"}), 400

        # Update request status
        execute_query(
            "UPDATE requests SET status = 'Rejected' WHERE ticket_uuid = %s",
            (request_uuid,),
            commit=True
        )

        create_log("Request Rejected",
                   f"Admin rejected request {request_uuid} for {request_item['wallet_name']}",
                   "Admin")

        # Add public log for request rejection
        create_log("Request Rejected",
                   f"A request from user {request_item['wallet_name']} has been rejected",
                   "Global")

        return jsonify({
            "message": f"Request {request_uuid} rejected successfully"
        })
    except Exception as e:
        print(f"Error rejecting request: {e}")
        return jsonify({"error": f"Failed to reject request: {str(e)}"}), 500


@app.route('/api/admin/purgeLogs', methods=['POST'])
@api_access_control
@admin_required
def api_admin_purge_logs():
    try:
        # Delete all logs
        execute_query("DELETE FROM logs", commit=True)

        # Create a new log for the purge action
        create_log("Logs Purged", "Admin purged all logs", "Admin")

        return jsonify({
            "message": "All logs purged successfully"
        })
    except Exception as e:
        print(f"Error purging logs: {e}")
        return jsonify({"error": f"Failed to purge logs: {str(e)}"}), 500


@app.route('/api/admin/mintCurrency', methods=['POST'])
@api_access_control
@admin_required
def api_admin_mint_currency():
    data = request.json

    form = CurrencyForm(data=data)

    if not form.validate():
        errors = {field: errors[0] for field, errors in form.errors.items()}
        return jsonify({"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

    amount = float(data.get('amount', 0))

    try:
        # Update maximum currency
        execute_query(
            "UPDATE settings SET maximum_currency = maximum_currency + %s",
            (amount,),
            commit=True
        )

        # Update admin balance
        update_admin_balance()

        settings = get_settings()

        create_log("Currency Minted",
                   f"Admin minted {amount} {settings['currency_name']}",
                   "Admin")

        # Add public log for currency minting
        create_log("Currency Minted",
                   f"{amount} {settings['currency_name']} has been added to the economy",
                   "Global")

        return jsonify({
            "message": f"{amount} {settings['currency_name']} minted successfully",
            "new_maximum": settings['maximum_currency']
        })
    except Exception as e:
        print(f"Error minting currency: {e}")
        return jsonify({"error": f"Failed to mint currency: {str(e)}"}), 500


@app.route('/api/admin/burnCurrency', methods=['POST'])
@api_access_control
@admin_required
def api_admin_burn_currency():
    data = request.json
    form = CurrencyForm(data=data)

    if not form.validate():
        errors = {field: errors[0] for field, errors in form.errors.items()}
        return jsonify({"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

    amount = float(data.get('amount', 0))

    settings = get_settings()
    total_currency = get_total_currency()

    free_currency = settings['maximum_currency'] - total_currency

    if amount > free_currency:
        return jsonify({"error": "Cannot burn more than available unallocated currency"}), 400

    try:
        # Update maximum currency
        execute_query(
            "UPDATE settings SET maximum_currency = maximum_currency - %s",
            (amount,),
            commit=True
        )

        # Update admin balance
        update_admin_balance()

        settings = get_settings()  # Refresh settings

        create_log("Currency Burned",
                   f"Admin burned {amount} {settings['currency_name']}",
                   "Admin")

        # Add public log for currency burning
        create_log("Currency Burned",
                   f"{amount} {settings['currency_name']} has been removed from the economy",
                   "Global")

        return jsonify({
            "message": f"{amount} {settings['currency_name']} burned successfully",
            "new_maximum": settings['maximum_currency']
        })
    except Exception as e:
        print(f"Error burning currency: {e}")
        return jsonify({"error": f"Failed to burn currency: {str(e)}"}), 500


# Web UI routes
@app.route('/wallet/<wallet_name>')
def wallet_page(wallet_name):
    if not validate_wallet_name(wallet_name):
        return render_template('error.html', message="Invalid wallet name format")

    user = get_user_by_wallet_name(wallet_name)

    if not user:
        return render_template('error.html', message="Wallet not found")

    settings = get_settings()

    return render_template('wallet.html', user=user, settings=settings,
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
    return render_template('api_docs.html', is_admin='admin' in session and session['admin'],
                           is_logged_in='wallet_name' in session)


@app.route('/about')
def about():
    if db_pool is None:
        return render_template('error.html', message="Database is not initialized")

    settings = get_settings()
    if not settings:
        return render_template('error.html', message="Database is not initialized")

    return render_template('about.html', settings=settings,
                           is_admin='admin' in session and session['admin'],
                           is_logged_in='wallet_name' in session)


# Serve static files
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)


# Database initialization
@app.before_request
def initialize_database():
    """Initialize database tables before first request"""
    if db_pool is not None:
        init_db()


if __name__ == '__main__':
    if ENV == 'production':
        serve(app, host='0.0.0.0', port=5000)
    else:
        app.run(ssl_context='adhoc', debug=True, port=5000)
