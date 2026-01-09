"""
Caching utilities for traffic analysis statistics.
Provides decorators and helper functions to cache expensive MongoDB queries.
"""
import hashlib
import json
from functools import wraps
from django.core.cache import caches
from django.conf import settings
import signal
import logging

logger = logging.getLogger(__name__)


class TimeoutException(Exception):
    """Raised when a query times out"""
    pass


def timeout_handler(signum, frame):
    """Signal handler for query timeout"""
    raise TimeoutException("Query timeout exceeded")


def with_timeout(timeout_seconds=5):
    """
    Decorator to add timeout to expensive functions.
    If function takes longer than timeout, returns None or raises TimeoutException.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Set up signal-based timeout (Unix only, but graceful fallback on Windows)
            try:
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(timeout_seconds)
                try:
                    result = func(*args, **kwargs)
                finally:
                    signal.alarm(0)  # Disable alarm
                return result
            except TimeoutException:
                logger.warning(f"{func.__name__} timed out after {timeout_seconds}s, returning None")
                return None
            except (ValueError, OSError):
                # signal.alarm not available on Windows, just call normally
                return func(*args, **kwargs)
        return wrapper
    return decorator


def get_cache_key(prefix, *args, **kwargs):
    """
    Generate a deterministic cache key from function arguments.
    
    Args:
        prefix: Cache key prefix (function name)
        *args: Positional arguments
        **kwargs: Keyword arguments
    
    Returns:
        str: Cache key
    """
    # Create a deterministic string from args and kwargs
    key_parts = [prefix]
    
    if args:
        key_parts.extend([str(arg) for arg in args])
    
    if kwargs:
        # Sort kwargs for deterministic ordering
        sorted_kwargs = sorted(kwargs.items())
        kwargs_str = json.dumps(sorted_kwargs, sort_keys=True)
        key_parts.append(kwargs_str)
    
    # Create hash for long keys
    key_string = ":".join(key_parts)
    if len(key_string) > 200:
        key_hash = hashlib.md5(key_string.encode()).hexdigest()
        return f"{prefix}:{key_hash}"
    
    return key_string.replace(" ", "_")


def cached_statistics(timeout=None, cache_alias='analytics', key_prefix='stats'):
    """
    Decorator to cache statistics function results in Redis.
    
    Args:
        timeout: Cache timeout in seconds (default: ANALYTICS_CACHE_TIMEOUT)
        cache_alias: Cache backend to use (default: 'analytics')
        key_prefix: Prefix for cache keys
    
    Usage:
        @cached_statistics(timeout=600)
        def get_total_events():
            return expensive_query()
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get the cache backend
            cache = caches[cache_alias]
            
            # Generate cache key
            func_name = f"{func.__module__}.{func.__name__}"
            cache_key = get_cache_key(f"{key_prefix}:{func_name}", *args, **kwargs)
            
            # Try to get from cache
            result = cache.get(cache_key)
            
            if result is not None:
                return result
            
            # Cache miss - call the function
            result = func(*args, **kwargs)
            
            # Store in cache
            cache_timeout = timeout if timeout is not None else settings.ANALYTICS_CACHE_TIMEOUT
            cache.set(cache_key, result, cache_timeout)
            
            return result
        
        return wrapper
    return decorator


def invalidate_statistics_cache(pattern='stats:*'):
    """
    Invalidate all statistics cache entries matching a pattern.
    
    Args:
        pattern: Redis key pattern (default: 'stats:*')
    
    Returns:
        int: Number of keys deleted
    """
    try:
        from django_redis import get_redis_connection
        redis_conn = get_redis_connection('analytics')
        
        # Get all keys matching pattern
        keys = redis_conn.keys(f"analytics:{pattern}")
        
        if keys:
            return redis_conn.delete(*keys)
        return 0
    except Exception as e:
        print(f"Error invalidating cache: {e}")
        return 0


def warm_cache(func, params_list):
    """
    Pre-populate cache for a function with multiple parameter sets.
    
    Args:
        func: Function to warm cache for
        params_list: List of (args, kwargs) tuples
    
    Example:
        warm_cache(get_total_events, [
            ((30, 30), {}),
            ((7, 7), {}),
        ])
    """
    results = []
    for args, kwargs in params_list:
        try:
            result = func(*args, **kwargs)
            results.append((args, kwargs, True))
        except Exception as e:
            results.append((args, kwargs, False, str(e)))
    
    return results
