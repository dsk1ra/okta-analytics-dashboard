#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    # Force the settings module to be config.settings, overriding any existing value
    os.environ["DJANGO_SETTINGS_MODULE"] = 'config.settings'
    
    # Add both the root directory and the apps directory to the Python path
    # This ensures that Python can find modules in both locations during the refactoring
    project_root = os.path.dirname(os.path.abspath(__file__))
    apps_dir = os.path.join(project_root, 'apps')
    
    # Add the project root to the Python path if it's not already there
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
        
    # Add the apps directory to the Python path if it's not already there
    if apps_dir not in sys.path:
        sys.path.insert(0, apps_dir)
    
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
