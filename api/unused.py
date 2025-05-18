from flask import jsonify

from bank_lib.database import check_db_connection, init_db
from bank_lib.decorator import admin_required


def register_unused_api_routes(app):
    # API Routes for database checks and initialization
    @app.route('/api/check-database', methods=['GET'])
    def api_check_database():
        """API endpoint to check database connection"""
        if check_db_connection():
            return jsonify({"status": "success", "message": "Database connection successful"})
        else:
            return jsonify({"status": "error",
                            "message": "Database connection failed. Please check your database configuration."}), 500

    @app.route('/api/init-database', methods=['POST'])
    @admin_required
    def api_init_database():
        """API endpoint to initialize database tables"""
        if init_db():
            return jsonify({"status": "success", "message": "Database tables created successfully"}), 200
        else:
            return jsonify({"status": "error",
                            "message": "Failed to create database tables. Please check your database configuration."}), 500
