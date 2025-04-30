from flask import jsonify, request, session

from banking.database import execute_query_dict
from banking.decorator import api_access_control, admin_required, login_required
from banking.get_data import get_settings, get_total_currency, get_server_health, get_user_by_wallet_name
from banking.validate import validate_wallet_name


def register_get_api_routes(app):
    @app.route('/api/get/health', methods=['GET'])
    @api_access_control
    @admin_required
    def api_server_health():
        """Get server health metrics"""
        return jsonify(get_server_health())

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
