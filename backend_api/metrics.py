from functools import wraps
import time
import statsd


statsd_client = statsd.StatsClient(
    host='localhost',  # StatsD host
    port=8125,        # default StatsD port
    prefix='webapp'    # application prefix
)

# Decorator to track API metrics using StatsD
def track_api_metrics(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        
        view_name = view_func.__name__

        statsd_client.incr(f'api.{view_name}.calls')  # Record API call counter
        
        api_start_time = time.time()

        try:
            response = view_func(request, *args, **kwargs)
            statsd_client.incr(f'api.{view_name}.status.{response.status_code}') # Record response status
            return response
        finally:
            duration = (time.time() - api_start_time) * 1000 # Record total API call duration
            statsd_client.timing(f'api.{view_name}.duration', duration)

    return wrapper

# context manager for timing database queries
class DatabaseQueryTimer:
    def __init__(self, operation_name):
        self.operation_name = operation_name
        
    def __enter__(self):
        self.start_time = time.time()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (time.time() - self.start_time) * 1000
        statsd_client.timing(f'database.{self.operation_name}.duration', duration)

# context manager for timing S3 operations
class S3OperationTimer:
    def __init__(self, operation_name):
        self.operation_name = operation_name
        
    def __enter__(self):
        self.start_time = time.time()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (time.time() - self.start_time) * 1000
        statsd_client.timing(f's3.{self.operation_name}.duration', duration)