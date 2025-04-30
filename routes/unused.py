from flask import jsonify

from banking.database import check_db_connection, init_db
from banking.decorator import api_access_control, admin_required


def register_unused_api_routes(app):
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
