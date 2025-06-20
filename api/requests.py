import re
import uuid

from flask import jsonify, request, session
from werkzeug.security import generate_password_hash

from bank_lib.database import execute_query, execute_query_dict
from bank_lib.decorator import login_required
from bank_lib.form_validators import ResetPasswordForm
from bank_lib.get_data import get_settings, get_client_ip, get_user_by_wallet_name
from bank_lib.log_module import create_log


def register_request_api_routes(app):
    @app.route('/api/request/wallet', methods=['POST'])
    def api_request_wallet():
        """API endpoint to request a new wallet"""
        data = request.json
        wallet_name = data.get('wallet_name')
        password = data.get('password')
        reason = data.get('reason')
        FORBIDDEN_REASON_CHARS = re.compile(r"[|\'\"`;]")

        if not password or len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters long"}), 400

        if not reason or len(reason) < 3 or FORBIDDEN_REASON_CHARS.search(reason):
            return jsonify({"error": "Reason must be at least 3 characters long"}), 400

        # Check if wallet already exists
        existing_wallet = get_user_by_wallet_name(wallet_name)
        if existing_wallet:
            return jsonify({"error": "Wallet name already exists"}), 400

        try:
            # Create a wallet creation request
            request_uuid = str(uuid.uuid4())

            # Store the hashed password in the reason field for security
            # Format: "Original reason | HASHED_PASSWORD"
            hashed_password = generate_password_hash(password)
            request_reason = f"{reason} | {hashed_password}"

            execute_query(
                """
                INSERT INTO requests
                (request_type, ticket_uuid, wallet_name, category, status, reason, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                ("WalletCreation", request_uuid, wallet_name, "Account", "Pending", request_reason, get_client_ip()),
                commit=True
            )

            create_log("Wallet Creation Request",
                       f"User requested wallet creation for {wallet_name}: {reason}",
                       "Admin")

            return jsonify({
                "message": "Wallet creation request submitted. An administrator will review your request.",
                "request_ticket_uuid": request_uuid
            })
        except Exception as e:
            print(f"Error requesting wallet creation: {e}")
            return jsonify({"error": f"Failed to submit wallet creation request: {str(e)}"}), 500

    @app.route('/api/request/refund', methods=['POST'])
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
    @login_required
    def api_request_reset_password():
        data = request.json
        form = ResetPasswordForm(data=data)

        if not form.validate():
            errors = {field: errors[0] for field, errors in form.errors.items()}
            return jsonify(
                {"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

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

    @app.route('/api/request/deleteAccount', methods=['POST'])
    @login_required
    def api_request_delete_account():
        data = request.json
        reason = data.get('reason')
        FORBIDDEN_REASON_CHARS = re.compile(r"[|\'\"`;]")

        if not reason or len(reason) < 3 or FORBIDDEN_REASON_CHARS.search(reason):
            return jsonify({"error": "Reason must be at least 3 characters long and must not contain forbidden characters"}), 400

        wallet_name = session['wallet_name']

        if wallet_name == "admin":
            return jsonify({"error": "You cannot delete admin accounts"}), 403

        try:
            delete_uuid = str(uuid.uuid4())

            # Create deletion request
            execute_query(
                """
                INSERT INTO requests
                (request_type, ticket_uuid, wallet_name, category, status, reason, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                ("AccountDeletion", delete_uuid, wallet_name, "Account", "Pending", reason, get_client_ip()),
                commit=True
            )

            create_log("Account Deletion Request",
                       f"{wallet_name} requested account deletion: {reason}",
                       "Admin")

            return jsonify({
                "message": "Account deletion request submitted. An administrator will review your request.",
                "request_ticket_uuid": delete_uuid
            })
        except Exception as e:
            print(f"Error requesting account deletion: {e}")
            return jsonify({"error": f"Account deletion request failed: {str(e)}"}), 500
