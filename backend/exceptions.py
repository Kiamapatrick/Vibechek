class DatabaseUnavailableError(Exception):
    """Raised when MongoDB is unreachable after all retry attempts."""
