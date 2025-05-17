import os

from flask import jsonify, request
from werkzeug.security import generate_password_hash

from bank_lib.database import is_db_initialized, execute_query
from bank_lib.decorator import api_access_control, admin_required
from bank_lib.form_types import SetupForm, WalletForm
from bank_lib.get_data import get_settings, get_total_currency, get_user_by_wallet_name, \
    update_admin_balance
from bank_lib.log_module import create_log


def register_setup_api_routes(app):
    @app.route('/api/setup', methods=['POST'])
    @api_access_control
    def api_setup():
        if is_db_initialized():
            return jsonify({"error": "Bank already initialized"}), 400

        data = request.json
        form = SetupForm(data=data)

        if not form.validate():
            errors = {field: errors[0] for field, errors in form.errors.items()}
            return jsonify(
                {"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

        bank_name = data.get('bank_name')
        currency_name = data.get('currency_name')
        admin_password = data.get('admin_password')

        try:
            # Run DDL statements from schema.sql
            schema_path = os.path.join(os.path.dirname(__file__), '../extras/schema.sql')
            with open(schema_path, 'r') as f:
                ddl_script = f.read()

            # Assuming execute_query can run multiple statements if passed raw SQL
            for statement in ddl_script.split(';'):
                stmt = statement.strip()
                if stmt:
                    try:
                        execute_query(stmt + ';', commit=True)
                    except Exception as e:
                        return jsonify({"error": "Failed to submit query to construct database", "details": f"{stmt} --> {e}"})

            # Insert settings
            execute_query(
                "INSERT INTO settings (bank_name, currency_name) VALUES (%s, %s, %s)",
                (bank_name, currency_name),
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
            return jsonify(
                {"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

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
                       f"Admin created wallet for {username} with {initial_currency} {settings['currency_name']}",
                       "Admin")

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
