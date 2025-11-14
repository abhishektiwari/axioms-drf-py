"""End-to-end tests for JWT issuer claim validation.

Tests the issuer validation feature that validates the 'iss' claim in JWT tokens
to ensure cryptographic keys belong to the expected issuer, preventing token
substitution attacks.
"""

import json
import time
import pytest
import django
from django.conf import settings
from django.test import override_settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.test import APIRequestFactory
from jwcrypto import jwk
from axioms_drf.authentication import HasValidAccessToken
from axioms_drf.permissions import HasAccessTokenScopes
from tests.conftest import generate_jwt_token

# Configure Django settings before importing models
if not settings.configured:
    settings.configure(
        SECRET_KEY='test-key',
        INSTALLED_APPS=['django.contrib.contenttypes', 'rest_framework'],
        AXIOMS_AUDIENCE='test-audience',
        AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json',
        CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
    )
    django.setup()


# Test view
class PrivateAPIView(APIView):
    """Test API view with authentication."""
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenScopes]
    access_token_scopes = ['openid', 'profile']

    def get(self, request):
        return Response({'message': 'Private endpoint'}, status=status.HTTP_200_OK)


@pytest.fixture
def view():
    """Create test view."""
    return PrivateAPIView.as_view()


class TestIssuerValidation:
    """Test issuer claim validation for token security."""

    def test_valid_token_with_matching_issuer(self, factory, view, test_key):
        """Test that token with matching issuer is accepted."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Private endpoint'

    def test_token_with_wrong_issuer(self, factory, view, test_key):
        """Test that token with wrong issuer is rejected."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://malicious-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 401

    def test_token_without_issuer_claim_when_validation_enabled(self, factory, view, test_key):
        """Test that token without issuer is rejected when validation is enabled."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 401

    @override_settings(AXIOMS_DOMAIN='test-domain.com', AXIOMS_JWKS_URL=None, AXIOMS_ISS_URL=None)
    def test_issuer_derived_from_domain(self, factory, view, test_key):
        """Test that issuer is correctly derived from AXIOMS_DOMAIN."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://test-domain.com',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200

    @override_settings(AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json', AXIOMS_ISS_URL=None, AXIOMS_DOMAIN=None)
    def test_backward_compatibility_no_issuer_validation(self, factory, view, test_key):
        """Test backward compatibility: tokens without issuer work when validation not configured."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Private endpoint'

    @override_settings(AXIOMS_ISS_URL='https://auth.example.com/oauth2')
    def test_issuer_with_path(self, factory, view, test_key):
        """Test that issuer URL with path is correctly validated."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://auth.example.com/oauth2',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200

    @override_settings(AXIOMS_ISS_URL='https://auth.example.com/oauth2')
    def test_issuer_mismatch_with_path(self, factory, view, test_key):
        """Test that issuer path must match exactly."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'iss': 'https://auth.example.com/different',  # Different path
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 401
