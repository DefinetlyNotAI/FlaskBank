from .database import execute_query
from .get_data import get_client_ip


# Add log rotation for the logs table to prevent it from growing indefinitely
def rotate_logs():
    """Archive old logs to prevent the logs table from growing indefinitely"""
    try:
        # Archive logs older than 30 days
        execute_query(
            """
            INSERT INTO logs_archive (id, action, details, timestamp, private_level, ip_address)
            SELECT id, action, details, timestamp, private_level, ip_address
            FROM logs
            WHERE timestamp < NOW() - INTERVAL '30 days'
            """,
            commit=True
        )

        # Delete archived logs from the main logs table
        execute_query(
            "DELETE FROM logs WHERE timestamp < NOW() - INTERVAL '30 days'",
            commit=True
        )

        print("Log Archival: Log rotation completed successfully.")
    except Exception as e:
        print(f"Log Archival: Error during log rotation: {e}")


# Create a log entry in the database
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
