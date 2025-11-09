"""Pytest configuration and shared fixtures for axioms-drf-py tests."""

import json
import pytest
from jwcrypto import jwk
from jwcrypto import jwt as jwcrypto_jwt


@pytest.fixture
def test_key():
    """Generate test RSA key for JWT signing."""
    key = jwk.JWK.generate(kty='RSA', size=2048, kid='test-key-id')
    return key


@pytest.fixture
def mock_jwks_data(test_key):
    """Generate mock JWKS data from test key."""
    public_key = test_key.export_public(as_dict=True)
    jwks = {'keys': [public_key]}
    return json.dumps(jwks).encode('utf-8')


@pytest.fixture(autouse=True)
def mock_jwks_fetch(monkeypatch, mock_jwks_data):
    """Mock JWKS fetch to return test keys."""
    from axioms_drf import helper

    class MockCacheFetcher:
        def fetch(self, url, max_age=300):
            return mock_jwks_data

    monkeypatch.setattr(helper, 'CacheFetcher', MockCacheFetcher)


@pytest.fixture
def apply_middleware():
    """Apply AccessTokenMiddleware to a request."""
    from axioms_drf.middleware import AccessTokenMiddleware

    def _apply(request):
        middleware = AccessTokenMiddleware(get_response=lambda r: None)
        middleware.process_request(request)
        return request

    return _apply


@pytest.fixture
def factory():
    """Create API request factory that applies middleware automatically."""
    from rest_framework.test import APIRequestFactory
    from axioms_drf.middleware import AccessTokenMiddleware

    class MiddlewareAPIRequestFactory(APIRequestFactory):
        def generic(self, method, path, data='', content_type='application/octet-stream', secure=False, **extra):
            request = super().generic(method, path, data, content_type, secure, **extra)
            middleware = AccessTokenMiddleware(get_response=lambda r: None)
            middleware.process_request(request)
            return request

    return MiddlewareAPIRequestFactory()


def generate_jwt_token(key, claims, alg='RS256'):
    """Generate a JWT token with specified claims and algorithm.

    Args:
        key: JWK key for signing.
        claims: Dictionary or JSON string of claims.
        alg: Algorithm to use (default: RS256).

    Returns:
        str: Serialized JWT token.
    """
    token = jwcrypto_jwt.JWT(
        header={"alg": alg, "kid": key.kid},
        claims=claims
    )
    token.make_signed_token(key)
    return token.serialize()
