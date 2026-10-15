"""Minimal Django settings for the simulated Platform API.

Deliberately slim: SQLite, no auth backends, no Celery, no cache. The only
things that matter here are the exercise endpoints and the Threat Intel client.
"""

from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'interview-only-not-a-secret'
DEBUG = True
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.staticfiles',
    'rest_framework',
    'drf_spectacular',
    'inventory',
]

MIDDLEWARE = [
    'django.middleware.common.CommonMiddleware',
]

ROOT_URLCONF = 'interview_api.urls'
WSGI_APPLICATION = 'interview_api.wsgi.application'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {'context_processors': []},
    },
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [],
    'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.AllowAny'],
    'UNAUTHENTICATED_USER': None,
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

# Interactive docs at /api/docs/, see inventory/openapi.py. Documentation only.
SPECTACULAR_SETTINGS = {
    'TITLE': 'Platform API (simulated)',
    'VERSION': '0.1.0',
    'DESCRIPTION': (
        'The four exercise endpoints. Every request is scoped to a tenant by the `X-Tenant-Id` header: '
        'click **Authorize** and enter `1` (Acme Industries) or `2` (Globex). Without it the API assumes tenant 1.\n\n'
        'The simulated Threat Intel has its own docs at http://localhost:8001/api/docs.'
    ),
    'SERVE_INCLUDE_SCHEMA': False,
    'APPEND_COMPONENTS': {
        'securitySchemes': {
            'TenantId': {
                'type': 'apiKey',
                'in': 'header',
                'name': 'X-Tenant-Id',
                'description': 'Stand-in for the real auth layer: the id of the tenant the request acts for.',
            }
        }
    },
    'SECURITY': [{'TenantId': []}],
}

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = False
USE_TZ = True

STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Pagination bounds for the applications listing.
API_PAGE_SIZE = 25
API_MAX_PAGE_SIZE = 100

# Threat Intel, the vulnerability intelligence service. `make dev` runs the simulated
# one on :8001 with this key.
THREAT_INTEL_URL = 'http://127.0.0.1:8001'
THREAT_INTEL_API_KEY = 'interview-threat-intel-key'
THREAT_INTEL_TIMEOUT_SECONDS = 10.0
# Threat Intel answers 413 to larger CVE detail batches.
THREAT_INTEL_MAX_CVE_BATCH_SIZE = 100
# A CVE's details are considered fresh for this long before Threat Intel is asked again.
VULNERABILITY_CACHE_TTL = timedelta(hours=12)
