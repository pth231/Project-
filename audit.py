"""
Append-only audit log. Each entry is FALCON-signed, 
following the signing pattern in crypto_utils.py.
"""


def log_event(action: str, user_id: str, detail: str) -> None:
    """
    Log an event to the append-only audit log.
    Each entry is signed with FALCON to ensure integrity.
    
    Args:
        action: event action type (e.g., "LOGIN", "ORDER_PLACED")
        user_id: ID of user performing the action
        detail: additional event details
    """
    pass


def verify_log_integrity() -> bool:
    """
    Verify the integrity of the entire audit log.
    Checks all FALCON signatures are valid.
    
    Returns:
        True if all signatures valid, False otherwise
    """
    pass
