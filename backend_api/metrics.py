# metrics.py
from functools import wraps
import time
import statsd  # Import the module
import logging

logger = logging.getLogger(__name__)

# Initialize StatsD client - use statsd.client instead of StatsD
statsd_client = statsd.StatsClient(
    host='localhost',  # Your StatsD host
    port=8125,        # Default StatsD port
    prefix='myapp'    # Your application prefix
)

def track_api_metrics(view_func):
    """Decorator to track API metrics using StatsD"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # Get view name for metric naming
        view_name = view_func.__name__

        # Increment API call counter
        statsd_client.incr(f'api.{view_name}.calls')

        # Start timing the entire API call
        api_timer = time.time()

        try:
            response = view_func(request, *args, **kwargs)
            # Record response status
            statsd_client.incr(f'api.{view_name}.status.{response.status_code}')
            return response
        finally:
            # Record total API call duration
            duration = (time.time() - api_timer) * 1000  # Convert to milliseconds
            statsd_client.timing(f'api.{view_name}.duration', duration)

    return wrapper

# Database query timer context manager
class DatabaseQueryTimer:
    def __init__(self, operation_name):
        self.operation_name = operation_name
        
    def __enter__(self):
        self.start_time = time.time()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (time.time() - self.start_time) * 1000  # Convert to milliseconds
        statsd_client.timing(f'database.{self.operation_name}.duration', duration)

# S3 operation timer context manager
class S3OperationTimer:
    def __init__(self, operation_name):
        self.operation_name = operation_name
        
    def __enter__(self):
        self.start_time = time.time()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (time.time() - self.start_time) * 1000  # Convert to milliseconds
        statsd_client.timing(f's3.{self.operation_name}.duration', duration)