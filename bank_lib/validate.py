import uuid


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
