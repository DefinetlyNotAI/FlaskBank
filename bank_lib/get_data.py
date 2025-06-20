import platform
import time

import psutil
from flask import g, request

from .database import execute_query_dict, execute_query, check_db_connection
from .global_vars import DB_POOL


# Get total currency in circulation
def get_total_currency():
    """Get the total currency in circulation"""
    try:
        result = execute_query("SELECT COALESCE(SUM(current_currency), 0) FROM users WHERE wallet_name != 'admin'")
        return result[0][0] if result else 0
    except Exception as e:
        print(f"Error getting total currency: {e}")
        return 0


# Get application settings in global table context
def get_settings():
    """Get application settings"""
    if 'settings' not in g:
        try:
            g.settings = execute_query_dict("SELECT * FROM settings LIMIT 1")
            g.settings = g.settings[0] if g.settings else None
        except Exception as e:
            print(f"Error getting settings: {e}")
            g.settings = None
    return g.settings


# Get user info by the wallet name
def get_user_by_wallet_name(wallet_name):
    """Always get user by wallet name directly from the database"""
    try:
        users = execute_query_dict(
            "SELECT * FROM users WHERE wallet_name = %s",
            (wallet_name,)
        )
        return users[0] if users else None
    except Exception as e:
        print(f"Error getting user by wallet name: {e}")
        return None


# Get server health metrics
def get_server_health():
    """Get server health metrics"""
    try:
        # System metrics
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
                "status": "good" if uptime_seconds < 31536000 else "warning" if uptime_seconds < 63072000 else "critical"
                # 1 year then 2 years
            },
            {
                "name": "Python Version",
                "value": platform.python_version(),
                "status": "good" if platform.python_version_tuple() >= ('3',
                                                                        '11') else "warning" if platform.python_version_tuple() >= (
                    '3', '8') else "critical"
            },
            {
                "name": "Database Connection Pool",
                "value": f"Min: {DB_POOL.minconn}, Max: {DB_POOL.maxconn}" if DB_POOL else "Not available",
                "status": "good" if DB_POOL else "critical"
            },
            {
                "name": "Memory Usage",
                "value": f"{memory.used / (1024 * 1024):.2f} MB / {memory.total / (1024 * 1024):.2f} MB ({memory_percent}%)",
                "status": "good" if memory_percent < 80 else "warning" if memory_percent < 90 else "critical"
            },
            {
                "name": "Disk Space",
                "value": f"{disk.used / (1024 * 1024 * 1024):.2f} GB / {disk.total / (1024 * 1024 * 1024):.2f} GB ({disk_percent}%)",
                "status": "good" if disk_percent < 80 else "warning" if disk_percent < 95 else "critical"
            }
        ]

        return {
            "system": {
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


# Get the client IP address
def get_client_ip():
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    else:
        return request.remote_addr
