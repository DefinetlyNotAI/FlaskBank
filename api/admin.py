import re
import uuid

from flask import jsonify, request
from werkzeug.security import generate_password_hash

from bank_lib.database import execute_query, execute_query_dict
from bank_lib.decorator import api_access_control, admin_required
from bank_lib.form_validators import SqlQueryForm, AdminActionForm, CurrencyForm
from bank_lib.get_data import get_settings, get_total_currency, get_user_by_wallet_name, \
    update_admin_balance
from bank_lib.log_module import create_log
from bank_lib.validate import validate_uuid


def sync_admin_wallet():
    try:
        settings = get_settings()
        total_used = get_total_currency()
        expected_admin_balance = settings['maximum_currency'] - total_used

        # Update the admin wallet to reflect the remainder
        execute_query(
            "UPDATE users SET current_currency = %s WHERE wallet_name = 'admin'",
            (expected_admin_balance,),
            commit=True
        )
    except Exception as e:
        print(e)


def register_admin_api_routes(app):
    @app.route('/api/admin/burnWallet', methods=['POST'])
    @api_access_control
    @admin_required
    def api_admin_burn_wallet():
        data = request.json
        form = AdminActionForm(data=data)

        if not form.validate():
            errors = {field: errors[0] for field, errors in form.errors.items()}
            return jsonify(
                {"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

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
        finally:
            sync_admin_wallet()

    @app.route('/api/admin/freezeWallet', methods=['POST'])
    @api_access_control
    @admin_required
    def api_admin_freeze_wallet():
        data = request.json
        form = AdminActionForm(data=data)

        if not form.validate():
            errors = {field: errors[0] for field, errors in form.errors.items()}
            return jsonify(
                {"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

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
            return jsonify(
                {"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

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
            return jsonify(
                {"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

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
        finally:
            sync_admin_wallet()

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
                                                       f" {amount} {settings['currency_name']} refunded from {recipient} to {sender}",
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
            elif request_item['request_type'] == "WalletCreation":
                # Process wallet creation
                wallet_name = request_item['wallet_name']

                # Extract the hashed password from the reason field
                # Format: "Original reason | HASHED_PASSWORD"
                parts = request_item['reason'].split(' | ')
                if len(parts) >= 2:
                    hashed_password = parts[-1]  # The last part is the hashed password

                    # Create the wallet with 0 initial currency
                    execute_query(
                        "INSERT INTO users (wallet_name, password, current_currency) VALUES (%s, %s, %s)",
                        (wallet_name, hashed_password, 0),
                        commit=True
                    )

                    # Update admin balance
                    update_admin_balance()

                    create_log("Wallet Creation",
                               f"Admin created wallet for {wallet_name}",
                               "Admin")

                    # Add public log for wallet creation
                    create_log("New Wallet",
                               f"User {wallet_name} joined the bank with 0 {settings['currency_name']}",
                               "Global")
                else:
                    create_log("Wallet Creation Failed",
                               f"Failed to create wallet for {wallet_name}: Invalid request format",
                               "Admin")
                    return jsonify({"error": "Invalid wallet creation request format"}), 400

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
        finally:
            sync_admin_wallet()

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
            return jsonify(
                {"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

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
        finally:
            sync_admin_wallet()

    @app.route('/api/admin/burnCurrency', methods=['POST'])
    @api_access_control
    @admin_required
    def api_admin_burn_currency():
        data = request.json
        form = CurrencyForm(data=data)

        if not form.validate():
            errors = {field: errors[0] for field, errors in form.errors.items()}
            return jsonify(
                {"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

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
        finally:
            sync_admin_wallet()

    @app.route('/api/admin/sql', methods=['POST'])
    @api_access_control
    @admin_required
    def api_admin_sql():
        """Execute SQL query"""
        data = request.json
        form = SqlQueryForm(data=data)

        if not form.validate():
            errors = {field: errors[0] for field, errors in form.errors.items()}
            return jsonify(
                {"error": errors.get(next(iter(errors), "error"), "Validation failed"), "details": errors}), 400

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
        finally:
            sync_admin_wallet()

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
        finally:
            sync_admin_wallet()
