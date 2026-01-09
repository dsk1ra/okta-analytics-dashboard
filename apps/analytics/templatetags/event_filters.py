from django import template
import json

register = template.Library()

@register.filter
def get_item(obj, key):
    """
    Gets an item from a dictionary or object by key.
    Can handle nested lookups with dot notation.
    """
    if obj is None:
        return None
    
    # Check if key exists directly
    if hasattr(obj, 'get') and callable(obj.get):
        return obj.get(key)
    elif hasattr(obj, key):
        return getattr(obj, key)
    elif isinstance(obj, dict) and key in obj:
        return obj[key]
    
    return None

@register.filter
def pprint(obj):
    """
    Pretty print a JSON object in a template
    """
    if isinstance(obj, str):
        return obj
    try:
        return json.dumps(obj, indent=2)
    except:
        return str(obj)