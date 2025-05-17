import re
import uuid


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
