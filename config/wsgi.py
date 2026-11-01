"""Serve the Django app; Python 3.12+, dependency: Django [needs Linux runner]."""
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
application = get_wsgi_application()
