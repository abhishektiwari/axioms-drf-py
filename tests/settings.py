"""Django settings for testing axioms-drf-py."""

SECRET_KEY = 'test-secret-key-for-axioms-drf-py-tests'

DEBUG = True

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'rest_framework',
]

MIDDLEWARE = [
    'axioms_drf.middleware.AccessTokenMiddleware',
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Axioms configuration
AXIOMS_AUDIENCE = 'test-audience'
AXIOMS_DOMAIN = None
AXIOMS_ISS_URL = 'https://test-domain.com'
AXIOMS_JWKS_URL = 'https://test-domain.com/.well-known/jwks.json'

# Cache configuration for JWKS caching
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}

# REST Framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [],
    'DEFAULT_PERMISSION_CLASSES': [],
    'TEST_REQUEST_DEFAULT_FORMAT': 'json',
}

USE_TZ = True
