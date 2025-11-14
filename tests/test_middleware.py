"""Tests for AccessTokenMiddleware.

This module tests the middleware's configuration validation, token parsing,
and error handling capabilities.
"""

import json
import time
import pytest
from django.test import override_settings
from rest_framework.test import APIRequestFactory
from axioms_drf.middleware import AccessTokenMiddleware
from tests.conftest import generate_jwt_token


class TestMiddlewareConfigurationValidation:
    """Test middleware configuration validation."""

    def test_missing_audience_raises_exception(self, monkeypatch):
        """Test that missing AXIOMS_AUDIENCE raises exception."""
        from django.conf import settings

        # Remove AXIOMS_AUDIENCE
        monkeypatch.delattr(settings, 'AXIOMS_AUDIENCE', raising=False)

        factory = APIRequestFactory()
        request = factory.get('/test')
        middleware = AccessTokenMiddleware(get_response=lambda r: None)

        with pytest.raises(Exception, match="AXIOMS_AUDIENCE is required"):
            middleware.process_request(request)

    def test_empty_audience_raises_exception(self):
        """Test that empty AXIOMS_AUDIENCE raises exception."""
        with override_settings(AXIOMS_AUDIENCE=''):
            factory = APIRequestFactory()
            request = factory.get('/test')
            middleware = AccessTokenMiddleware(get_response=lambda r: None)

            with pytest.raises(Exception, match="AXIOMS_AUDIENCE is required"):
                middleware.process_request(request)

    def test_missing_all_jwks_sources_raises_exception(self, monkeypatch):
        """Test that missing all JWKS sources raises exception."""
        from django.conf import settings

        # Remove all JWKS sources
        monkeypatch.delattr(settings, 'AXIOMS_JWKS_URL', raising=False)
        monkeypatch.delattr(settings, 'AXIOMS_ISS_URL', raising=False)
        monkeypatch.delattr(settings, 'AXIOMS_DOMAIN', raising=False)

        factory = APIRequestFactory()
        request = factory.get('/test')
        middleware = AccessTokenMiddleware(get_response=lambda r: None)

        with pytest.raises(Exception, match="JWKS URL configuration required"):
            middleware.process_request(request)

    def test_valid_with_jwks_url_only(self):
        """Test that middleware works with only AXIOMS_JWKS_URL configured."""
        with override_settings(
            AXIOMS_AUDIENCE='test-audience',
            AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json',
            AXIOMS_ISS_URL=None,
            AXIOMS_DOMAIN=None
        ):
            factory = APIRequestFactory()
            request = factory.get('/test')
            middleware = AccessTokenMiddleware(get_response=lambda r: None)

            # Should not raise exception
            middleware.process_request(request)
            assert hasattr(request, 'auth_jwt')
            assert hasattr(request, 'missing_auth_header')
            assert hasattr(request, 'invalid_bearer_token')

    def test_valid_with_iss_url_only(self):
        """Test that middleware works with only AXIOMS_ISS_URL configured."""
        with override_settings(
            AXIOMS_AUDIENCE='test-audience',
            AXIOMS_JWKS_URL=None,
            AXIOMS_ISS_URL='https://test-domain.com',
            AXIOMS_DOMAIN=None
        ):
            factory = APIRequestFactory()
            request = factory.get('/test')
            middleware = AccessTokenMiddleware(get_response=lambda r: None)

            # Should not raise exception
            middleware.process_request(request)
            assert hasattr(request, 'auth_jwt')

    def test_valid_with_domain_only(self):
        """Test that middleware works with only AXIOMS_DOMAIN configured."""
        with override_settings(
            AXIOMS_AUDIENCE='test-audience',
            AXIOMS_JWKS_URL=None,
            AXIOMS_ISS_URL=None,
            AXIOMS_DOMAIN='test-domain.com'
        ):
            factory = APIRequestFactory()
            request = factory.get('/test')
            middleware = AccessTokenMiddleware(get_response=lambda r: None)

            # Should not raise exception
            middleware.process_request(request)
            assert hasattr(request, 'auth_jwt')


class TestMiddlewareTokenParsing:
    """Test middleware token parsing logic."""

    def test_missing_authorization_header_sets_flag(self, apply_middleware):
        """Test that missing Authorization header sets missing_auth_header flag."""
        factory = APIRequestFactory()
        request = factory.get('/test')
        request = apply_middleware(request)

        assert request.missing_auth_header is True
        assert request.auth_jwt is None
        assert request.invalid_bearer_token is False

    def test_invalid_bearer_format_sets_flag(self, apply_middleware):
        """Test that invalid Bearer format sets invalid_bearer_token flag."""
        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION='InvalidBearer token')
        request = apply_middleware(request)

        assert request.invalid_bearer_token is True
        assert request.auth_jwt is None
        assert request.missing_auth_header is False

    def test_bearer_without_token_sets_flag(self, apply_middleware):
        """Test that 'Bearer' without token sets invalid_bearer_token flag."""
        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION='Bearer')
        request = apply_middleware(request)

        assert request.invalid_bearer_token is True
        assert request.auth_jwt is None

    def test_bearer_with_only_spaces_sets_flag(self, apply_middleware):
        """Test that 'Bearer' with only spaces sets invalid_bearer_token flag."""
        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION='Bearer   ')
        request = apply_middleware(request)

        assert request.invalid_bearer_token is True
        assert request.auth_jwt is None

    def test_valid_bearer_token_sets_auth_jwt(self, apply_middleware, test_key):
        """Test that valid Bearer token sets auth_jwt attribute."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION=f'Bearer {token}')
        request = apply_middleware(request)

        assert request.auth_jwt is not None
        assert request.auth_jwt is not False
        assert request.auth_jwt.sub == 'user123'
        assert request.missing_auth_header is False
        assert request.invalid_bearer_token is False

    def test_bearer_token_with_multiple_spaces_handled_correctly(self, apply_middleware, test_key):
        """Test that Bearer token with multiple spaces is handled correctly."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user456',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        # Multiple spaces between Bearer and token
        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION=f'Bearer   {token}')
        request = apply_middleware(request)

        # Should still work because of token.strip()
        assert request.auth_jwt is not None
        assert request.auth_jwt is not False
        assert request.auth_jwt.sub == 'user456'

    def test_bearer_case_insensitive(self, apply_middleware, test_key):
        """Test that 'bearer' (lowercase) is accepted."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user789',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION=f'bearer {token}')
        request = apply_middleware(request)

        assert request.auth_jwt is not None
        assert request.auth_jwt.sub == 'user789'

    def test_invalid_token_sets_auth_jwt_to_false(self, apply_middleware):
        """Test that invalid token sets auth_jwt to False."""
        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION='Bearer invalid.token.here')
        request = apply_middleware(request)

        assert request.auth_jwt is False
        assert request.missing_auth_header is False
        assert request.invalid_bearer_token is False

    def test_expired_token_sets_auth_jwt_to_false(self, apply_middleware, test_key):
        """Test that expired token sets auth_jwt to False."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user999',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now - 3600,  # Expired 1 hour ago
            'iat': now - 7200
        })

        token = generate_jwt_token(test_key, claims)
        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION=f'Bearer {token}')
        request = apply_middleware(request)

        assert request.auth_jwt is False

    def test_wrong_audience_sets_auth_jwt_to_false(self, apply_middleware, test_key):
        """Test that wrong audience sets auth_jwt to False."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user111',
            'aud': ['wrong-audience'],  # Wrong audience
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION=f'Bearer {token}')
        request = apply_middleware(request)

        assert request.auth_jwt is False


class TestMiddlewareErrorHandling:
    """Test middleware error handling."""

    def test_jwks_fetch_failure_sets_auth_jwt_to_false(self, monkeypatch, apply_middleware, test_key):
        """Test that JWKS fetch failure sets auth_jwt to False."""
        from axioms_drf import helper

        # Mock CacheFetcher to raise exception
        class FailingCacheFetcher:
            def fetch(self, url, max_age=300):
                raise Exception("Network error")

        monkeypatch.setattr(helper, 'CacheFetcher', FailingCacheFetcher)

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user222',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION=f'Bearer {token}')
        request = apply_middleware(request)

        # JWKS fetch failure should set auth_jwt to False
        assert request.auth_jwt is False

    def test_invalid_jwks_response_sets_auth_jwt_to_false(self, monkeypatch, apply_middleware, test_key):
        """Test that invalid JWKS response sets auth_jwt to False."""
        from axioms_drf import helper

        # Mock CacheFetcher to return invalid JWKS
        class InvalidJWKSFetcher:
            def fetch(self, url, max_age=300):
                return b'invalid json'

        monkeypatch.setattr(helper, 'CacheFetcher', InvalidJWKSFetcher)

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user333',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION=f'Bearer {token}')
        request = apply_middleware(request)

        # Invalid JWKS should set auth_jwt to False
        assert request.auth_jwt is False

    def test_missing_kid_in_jwks_sets_auth_jwt_to_false(self, monkeypatch, apply_middleware, test_key):
        """Test that missing kid in JWKS sets auth_jwt to False."""
        from axioms_drf import helper

        # Mock CacheFetcher to return JWKS without the requested kid
        class MissingKidFetcher:
            def fetch(self, url, max_age=300):
                # Return valid JWKS but with different kid
                different_key = helper.jwk.JWK.generate(kty='RSA', size=2048, kid='different-key-id')
                public_key = different_key.export_public(as_dict=True)
                jwks = {'keys': [public_key]}
                return json.dumps(jwks).encode('utf-8')

        monkeypatch.setattr(helper, 'CacheFetcher', MissingKidFetcher)

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user444',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION=f'Bearer {token}')
        request = apply_middleware(request)

        # Missing kid should set auth_jwt to False
        assert request.auth_jwt is False

    def test_wrong_issuer_sets_auth_jwt_to_false(self, apply_middleware, test_key):
        """Test that wrong issuer sets auth_jwt to False."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user555',
            'aud': ['test-audience'],
            'iss': 'https://wrong-issuer.com',  # Wrong issuer
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION=f'Bearer {token}')
        request = apply_middleware(request)

        assert request.auth_jwt is False

    def test_token_without_kid_sets_auth_jwt_to_false(self, apply_middleware, test_key):
        """Test that token without kid in header sets auth_jwt to False."""
        from jwcrypto import jwt as jwcrypto_jwt

        now = int(time.time())
        claims = json.dumps({
            'sub': 'user666',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        })

        # Create token without kid in header
        token = jwcrypto_jwt.JWT(
            header={"alg": "RS256"},  # No kid
            claims=claims
        )
        token.make_signed_token(test_key)
        token_str = token.serialize()

        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION=f'Bearer {token_str}')
        request = apply_middleware(request)

        # Token without kid should set auth_jwt to False
        assert request.auth_jwt is False


class TestMiddlewareRequestAttributes:
    """Test that middleware sets correct request attributes."""

    def test_request_attributes_initialized(self, apply_middleware):
        """Test that all request attributes are initialized."""
        factory = APIRequestFactory()
        request = factory.get('/test')
        request = apply_middleware(request)

        # Check all attributes exist
        assert hasattr(request, 'auth_jwt')
        assert hasattr(request, 'missing_auth_header')
        assert hasattr(request, 'invalid_bearer_token')

    def test_request_attributes_default_values(self, apply_middleware):
        """Test default values when no Authorization header."""
        factory = APIRequestFactory()
        request = factory.get('/test')
        request = apply_middleware(request)

        # Check default values
        assert request.auth_jwt is None
        assert request.missing_auth_header is True
        assert request.invalid_bearer_token is False

    def test_request_attributes_with_valid_token(self, apply_middleware, test_key):
        """Test attribute values with valid token."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user777',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scope': 'openid',
            'roles': ['admin'],
            'permissions': ['read:all'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        factory = APIRequestFactory()
        request = factory.get('/test', HTTP_AUTHORIZATION=f'Bearer {token}')
        request = apply_middleware(request)

        # Check attributes with valid token
        assert request.auth_jwt is not None
        assert request.auth_jwt is not False
        assert request.auth_jwt.sub == 'user777'
        assert request.auth_jwt.scope == 'openid'
        # Frozen Box converts lists to tuples for immutability
        assert request.auth_jwt.roles == ('admin',)
        assert request.auth_jwt.permissions == ('read:all',)
        assert request.auth_jwt.aud == ('test-audience',)
        assert request.missing_auth_header is False
        assert request.invalid_bearer_token is False
