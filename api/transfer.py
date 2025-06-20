import uuid

from flask import jsonify, request

from bank_lib.database import execute_query
from bank_lib.decorator import admin_required
from bank_lib.form_validators import BankTransferForm
from bank_lib.get_data import get_settings, get_client_ip, get_total_currency, get_user_by_wallet_name, \
    update_admin_balance
from bank_lib.log_module import create_log


def register_transfer_api_routes(app):
    # noinspection DuplicatedCode
    @app.route('/api/transfer/bank', methods=['POST'])
    @admin_required
    def api_transfer_bank():
        data = request.json
        form = BankTransferForm(data=data)

        if not form.validate():
            errors = {field: errors[0] for field, errors in form.errors.items()}
            return jsonify(
                {"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

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
