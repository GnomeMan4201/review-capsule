"""Parse PostgreSQL URLs without logging credentials; Python 3.12+, stdlib only."""
from urllib.parse import urlsplit, unquote, parse_qs


def postgres_config(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ('postgres', 'postgresql') or not parsed.hostname or not parsed.username or not parsed.path.strip('/'):
            raise ValueError
        port = parsed.port or 5432
        mode = parse_qs(parsed.query).get('sslmode', ['require'])[0]
        if mode not in ('require', 'verify-ca', 'verify-full', 'prefer', 'allow', 'disable'):
            raise ValueError
        return {'ENGINE': 'django.db.backends.postgresql', 'NAME': unquote(parsed.path[1:]),
                'USER': unquote(parsed.username), 'PASSWORD': unquote(parsed.password or ''),
                'HOST': parsed.hostname, 'PORT': str(port), 'OPTIONS': {'sslmode': mode}}
    except (ValueError, TypeError, AttributeError):
        raise ValueError('Invalid PostgreSQL DATABASE_URL configuration.') from None
