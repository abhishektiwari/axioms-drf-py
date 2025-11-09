"""End-to-end tests for JWT algorithm validation.

Tests algorithm validation to prevent algorithm confusion attacks and ensure
only secure asymmetric algorithms are accepted.
"""

import json
import time
import pytest
import base64
import django
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.test import APIRequestFactory
from jwcrypto import jwk
from jwcrypto import jwt as jwcrypto_jwt
from axioms_drf.authentication import HasValidAccessToken
from axioms_drf.permissions import HasAccessTokenScopes

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


def generate_jwt_token(key, claims, alg='RS256'):
    """Generate a JWT token with specified claims and algorithm."""
    token = jwcrypto_jwt.JWT(
        header={"alg": alg, "kid": key.kid},
        claims=claims
    )
    token.make_signed_token(key)
    return token.serialize()


def create_token_with_none_alg(claims):
    """Create a token with 'none' algorithm (security vulnerability)."""
    header = {"alg": "none", "typ": "JWT", "kid": "test-key-id"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    # 'none' algorithm has empty signature
    return f"{header_b64}.{payload_b64}."


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


class TestAlgorithmValidation:
    """Test JWT algorithm validation for security."""

    def test_valid_rs256_algorithm(self, factory, view, test_key):
        """Test that RS256 algorithm is accepted."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims, alg='RS256')
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200

    def test_reject_none_algorithm(self, factory, view):
        """Test that 'none' algorithm is rejected (critical security test)."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        }

        token = create_token_with_none_alg(claims)
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 401

    def test_reject_hs256_symmetric_algorithm(self, factory, view):
        """Test that symmetric algorithms like HS256 are rejected."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        }

        # Create a token with manipulated header claiming HS256
        header = {"alg": "HS256", "typ": "JWT", "kid": "test-key-id"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
        # Add fake signature
        signature_b64 = base64.urlsafe_b64encode(b'fake_signature').decode().rstrip('=')
        token = f"{header_b64}.{payload_b64}.{signature_b64}"

        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 401

    def test_reject_missing_algorithm(self, factory, view):
        """Test that tokens without algorithm are rejected."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        }

        # Create token without 'alg' header
        header = {"typ": "JWT", "kid": "test-key-id"}  # Missing 'alg'
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
        signature_b64 = base64.urlsafe_b64encode(b'fake_signature').decode().rstrip('=')
        token = f"{header_b64}.{payload_b64}.{signature_b64}"

        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 401

    def test_reject_missing_kid(self, factory, view, test_key):
        """Test that tokens without key ID are rejected."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        # Create token without 'kid'
        token_obj = jwcrypto_jwt.JWT(
            header={"alg": "RS256"},  # Missing 'kid'
            claims=claims
        )
        token_obj.make_signed_token(test_key)
        token = token_obj.serialize()

        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 401

    def test_invalid_jwt_format(self, factory, view):
        """Test that malformed JWT tokens are rejected."""
        # Token with invalid format (missing parts)
        token = "invalid.token"

        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 401
