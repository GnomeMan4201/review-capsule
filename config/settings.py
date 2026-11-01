import os
from pathlib import Path
from .db_url import postgres_config
from django.core.management.utils import get_random_secret_key
BASE_DIR=Path(__file__).resolve().parent.parent
DEBUG=os.environ.get('CAPSULE_DEBUG','1')=='1'
SECRET_KEY=os.environ.get('CAPSULE_SECRET_KEY') or (get_random_secret_key() if DEBUG else '')
if not SECRET_KEY: raise RuntimeError('Set CAPSULE_SECRET_KEY outside local demo mode')
ALLOWED_HOSTS=os.environ.get('CAPSULE_HOSTS','localhost,127.0.0.1,testserver').split(',')
RENDER_HOST=os.environ.get('RENDER_EXTERNAL_HOSTNAME','')
if RENDER_HOST: ALLOWED_HOSTS.append(RENDER_HOST)
INSTALLED_APPS=['django.contrib.auth','django.contrib.contenttypes','django.contrib.sessions','django.contrib.staticfiles','capsule']
MIDDLEWARE=['django.middleware.security.SecurityMiddleware','capsule.middleware.PrivateResponses','django.contrib.sessions.middleware.SessionMiddleware','django.middleware.common.CommonMiddleware','django.middleware.csrf.CsrfViewMiddleware','capsule.middleware.LoginThrottle','django.contrib.auth.middleware.AuthenticationMiddleware']
ROOT_URLCONF='config.urls'
TEMPLATES=[{'BACKEND':'django.template.backends.django.DjangoTemplates','DIRS':[], 'APP_DIRS':True,'OPTIONS':{'context_processors':['django.template.context_processors.request','django.contrib.auth.context_processors.auth','capsule.context.deployment']}}]
if os.environ.get('DATABASE_URL'):
    DATABASES={'default':postgres_config(os.environ['DATABASE_URL'])}
elif os.environ.get('CAPSULE_PG_DATABASE'):
    DATABASES={'default':{'ENGINE':'django.db.backends.postgresql','NAME':os.environ['CAPSULE_PG_DATABASE'],'USER':os.environ.get('CAPSULE_PG_USER','capsule'),'PASSWORD':os.environ.get('CAPSULE_PG_PASSWORD',''),'HOST':os.environ.get('CAPSULE_PG_HOST','localhost'),'PORT':os.environ.get('CAPSULE_PG_PORT','5432')}}
else:
    if not DEBUG:raise RuntimeError('SQLite is only for the local demo; configure PostgreSQL')
    DATABASES={'default':{'ENGINE':'django.db.backends.sqlite3','NAME':BASE_DIR/'demo.sqlite3','OPTIONS':{'timeout':20}}}
AUTH_PASSWORD_VALIDATORS=[{'NAME':'django.contrib.auth.password_validation.MinimumLengthValidator'}]
SYNTHETIC_DEMO=os.environ.get('CAPSULE_SYNTHETIC_DEMO','0')=='1'
CSRF_TRUSTED_ORIGINS=[v for v in os.environ.get('CAPSULE_ORIGINS','').split(',') if v]
if RENDER_HOST: CSRF_TRUSTED_ORIGINS.append('https://'+RENDER_HOST)
LOGIN_URL='/login/'
LOGIN_REDIRECT_URL='/'
LOGOUT_REDIRECT_URL='/login/'
USE_TZ=True
TIME_ZONE='UTC'
STATIC_URL='static/'
DEFAULT_AUTO_FIELD='django.db.models.BigAutoField'
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE='Strict'
CSRF_COOKIE_SAMESITE='Strict'
SECURE_CONTENT_TYPE_NOSNIFF=True
SECURE_REDIRECT_EXEMPT=[r'^healthz/$']
SECURE_REFERRER_POLICY='same-origin'
X_FRAME_OPTIONS='DENY'
DATA_UPLOAD_MAX_MEMORY_SIZE=262144
if not DEBUG:
    # Hosted ingress terminates TLS; verify the forwarded-header policy per host.
    SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO','https')
    SESSION_COOKIE_SECURE=True
    CSRF_COOKIE_SECURE=True
    SECURE_SSL_REDIRECT=True
    SECURE_HSTS_SECONDS=3600
