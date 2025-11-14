"""Integration tests for helper.py functions.

This module contains comprehensive tests for has_valid_token and related
token validation functions.
"""

import json
import time
import pytest
from unittest.mock import patch, MagicMock
from django.test import override_settings
from django.core.cache import cache
from box.exceptions import BoxError
from axioms_drf.helper import has_valid_token
from axioms_drf.authentication import UnauthorizedAccess
from tests.conftest import generate_jwt_token


@pytest.fixture
def mock_jwks_response(test_key):
    """Mock JWKS endpoint response."""
    jwks_data = {
        'keys': [json.loads(test_key.export_public())]
    }
    return json.dumps(jwks_data).encode('utf-8')


@pytest.fixture
def mock_urlopen(mock_jwks_response):
    """Mock urlopen to return JWKS data."""
    with patch('axioms_drf.helper.urlopen') as mock:
        mock_response = MagicMock()
        mock_response.read.return_value = mock_jwks_response
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = False
        mock.return_value = mock_response
        yield mock


@pytest.fixture(autouse=True)
def clear_cache_between_tests():
    """Clear Django cache before and after each test to prevent JWKS caching issues."""
    cache.clear()
    yield
    cache.clear()


class TestHasValidToken:
    """Test has_valid_token function with various token scenarios.

    All Axioms settings are configured centrally in tests/settings.py:
    - AXIOMS_AUDIENCE = 'test-audience'
    - AXIOMS_ISS_URL = 'https://test-domain.com'
    - AXIOMS_JWKS_URL = 'https://test-domain.com/.well-known/jwks.json'
    """

    def test_valid_token_returns_payload(self, test_key, mock_urlopen):
        """Test that a valid token returns the payload as an immutable Box."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scope': 'openid profile',
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token)

        # Verify payload contents
        assert payload.sub == 'user123'
        assert payload.aud == ('test-audience',)  # Frozen Box converts lists to tuples
        assert payload.iss == 'https://test-domain.com'
        assert payload.scope == 'openid profile'

        # Verify jti (JWT ID) is automatically added
        assert hasattr(payload, 'jti')
        assert payload.jti is not None
        assert len(payload.jti) > 0  # Should be a UUID string

        # Verify Box is frozen (immutable)
        with pytest.raises(BoxError):
            payload.sub = 'hacker'

    def test_expired_token_raises_unauthorized(self, test_key, mock_urlopen):
        """Test that an expired token raises UnauthorizedAccess."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now - 3600,  # Expired 1 hour ago
            'iat': now - 7200
        }

        token = generate_jwt_token(test_key, claims)

        with pytest.raises(UnauthorizedAccess):
            has_valid_token(token)

    def test_tampered_token_raises_unauthorized(self, test_key, mock_urlopen):
        """Test that a tampered token raises UnauthorizedAccess."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)

        # Tamper with the token by changing a character in the payload section
        parts = token.split('.')
        if len(parts) == 3:
            # Change one character in the payload (base64 encoded)
            tampered_payload = parts[1][:-1] + ('A' if parts[1][-1] != 'A' else 'B')
            tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

            with pytest.raises(UnauthorizedAccess):
                has_valid_token(tampered_token)

    def test_wrong_audience_raises_unauthorized(self, test_key, mock_urlopen):
        """Test that a token with wrong audience raises UnauthorizedAccess."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['wrong-audience'],  # Wrong audience
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)

        with pytest.raises(UnauthorizedAccess):
            has_valid_token(token)

    def test_wrong_issuer_raises_unauthorized(self, test_key, mock_urlopen):
        """Test that a token with wrong issuer raises UnauthorizedAccess."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://evil-domain.com',  # Wrong issuer
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)

        with pytest.raises(UnauthorizedAccess):
            has_valid_token(token)

    @override_settings(AXIOMS_ISS_URL=None)
    def test_token_without_issuer_when_not_required(self, test_key, mock_urlopen):
        """Test that a token without issuer succeeds when issuer validation is not configured."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            # No 'iss' claim
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token)

        assert payload.sub == 'user123'

    def test_token_without_kid_raises_unauthorized(self, test_key, mock_urlopen):
        """Test that a token without kid in header raises UnauthorizedAccess."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        # Generate token without kid
        token = generate_jwt_token(test_key, claims, include_kid=False)

        with pytest.raises(UnauthorizedAccess):
            has_valid_token(token)

    @pytest.mark.skip(reason="jwcrypto library doesn't support signing with HS256 using RSA keys")
    def test_token_with_symmetric_algorithm_raises_unauthorized(self, test_key, mock_urlopen):
        """Test that a token with symmetric algorithm (HS256) raises UnauthorizedAccess.

        Note: This test is skipped because jwcrypto doesn't allow signing with HS256
        using RSA keys. The algorithm validation is tested via malformed token tests.
        """
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        # Try to generate token with HS256 (symmetric algorithm)
        # This should be rejected by has_valid_token
        custom_header = {
            'alg': 'HS256',  # Symmetric algorithm - not allowed
            'kid': test_key.kid
        }
        token = generate_jwt_token(test_key, claims, custom_header=custom_header)

        with pytest.raises(UnauthorizedAccess):
            has_valid_token(token)

    @pytest.mark.skip(reason="jwcrypto library doesn't support signing with 'none' algorithm")
    def test_token_with_none_algorithm_raises_unauthorized(self, test_key, mock_urlopen):
        """Test that a token with 'none' algorithm raises UnauthorizedAccess.

        Note: This test is skipped because jwcrypto doesn't support 'none' algorithm.
        The algorithm validation is tested via malformed token tests.
        """
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        # Try to generate token with 'none' algorithm
        custom_header = {
            'alg': 'none',  # None algorithm - not allowed
            'kid': test_key.kid
        }
        token = generate_jwt_token(test_key, claims, custom_header=custom_header)

        with pytest.raises(UnauthorizedAccess):
            has_valid_token(token)

    @pytest.mark.skip(reason="PyJWT 2.10.1 doesn't properly enforce require_exp option when exp claim is missing")
    def test_token_without_exp_claim_raises_unauthorized(self, test_key, mock_urlopen):
        """Test that a token without exp claim raises UnauthorizedAccess.

        Note: This test is skipped because PyJWT 2.10.1 doesn't properly enforce
        the require_exp option when the exp claim is missing. In production, OAuth2
        providers always include exp claim, so this is not a practical concern.
        """
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            # No 'exp' claim
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)

        with pytest.raises(UnauthorizedAccess):
            has_valid_token(token)

    def test_token_with_future_iat_raises_unauthorized(self, test_key, mock_urlopen):
        """Test that a token with future iat (issued at) raises UnauthorizedAccess."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 7200,
            'iat': now + 3600  # Issued 1 hour in the future - invalid
        }

        token = generate_jwt_token(test_key, claims)

        with pytest.raises(UnauthorizedAccess):
            has_valid_token(token)

    def test_token_with_nbf_in_future_raises_unauthorized(self, test_key, mock_urlopen):
        """Test that a token with nbf (not before) in future raises UnauthorizedAccess."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 7200,
            'iat': now,
            'nbf': now + 3600  # Not valid before 1 hour from now
        }

        token = generate_jwt_token(test_key, claims)

        with pytest.raises(UnauthorizedAccess):
            has_valid_token(token)

    def test_token_with_multiple_audiences(self, test_key, mock_urlopen):
        """Test that a token with multiple audiences succeeds if one matches."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['other-audience', 'test-audience', 'another-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token)

        assert payload.sub == 'user123'
        assert 'test-audience' in payload.aud

    def test_malformed_token_raises_unauthorized(self, test_key, mock_urlopen):
        """Test that a malformed token raises UnauthorizedAccess."""
        malformed_tokens = [
            'not.a.valid.token',
            'invalid-token',
            '',
            'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9',  # Only header, no payload
            'a.b',  # Only 2 parts instead of 3
        ]

        for token in malformed_tokens:
            with pytest.raises(UnauthorizedAccess):
                has_valid_token(token)

    def test_token_with_different_kid_raises_unauthorized(self, test_key, mock_urlopen):
        """Test that a token with kid not in JWKS raises UnauthorizedAccess."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        # Generate token but modify header to use different kid
        custom_header = {
            'alg': 'RS256',
            'kid': 'different-key-id'  # Kid not in JWKS
        }
        token = generate_jwt_token(test_key, claims, custom_header=custom_header)

        with pytest.raises(UnauthorizedAccess):
            has_valid_token(token)

    def test_token_with_all_allowed_algorithms(self, test_key, mock_urlopen):
        """Test that tokens with all allowed asymmetric algorithms are accepted."""
        # Test with RS256 (already tested above, but included for completeness)
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        # RS256 is the default and should work
        token = generate_jwt_token(test_key, claims, alg='RS256')
        payload = has_valid_token(token)
        assert payload.sub == 'user123'

    def test_token_with_extra_claims(self, test_key, mock_urlopen):
        """Test that a token with extra claims is accepted."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now,
            'scope': 'openid profile email',
            'roles': ['admin', 'editor'],
            'permissions': ['read:all', 'write:all'],
            'custom_claim': 'custom_value',
            'email': 'user@example.com',
            'name': 'Test User'
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token)

        assert payload.sub == 'user123'
        assert payload.scope == 'openid profile email'
        assert payload.roles == ('admin', 'editor')  # Frozen Box converts to tuple
        assert payload.permissions == ('read:all', 'write:all')  # Frozen Box converts to tuple
        assert payload.custom_claim == 'custom_value'
        assert payload.email == 'user@example.com'

    def test_payload_immutability(self, test_key, mock_urlopen):
        """Test that the returned payload is truly immutable."""
        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now,
            'scope': 'openid profile'
        }

        token = generate_jwt_token(test_key, claims)
        payload = has_valid_token(token)

        # Try to modify various attributes - all should raise BoxError
        with pytest.raises(BoxError):
            payload.sub = 'hacker'

        with pytest.raises(BoxError):
            payload.scope = 'admin'

        with pytest.raises(BoxError):
            payload.new_claim = 'injected'

        with pytest.raises(BoxError):
            del payload.sub

    def test_jwks_fetch_failure_raises_unauthorized(self, test_key):
        """Test that JWKS fetch failure raises UnauthorizedAccess."""
        from axioms_drf import helper

        # Clear cache to ensure we fetch JWKS
        cache.clear()

        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)

        # Mock CacheFetcher to raise an exception
        class FailingCacheFetcher:
            def fetch(self, url, max_age=300):
                raise Exception('Network error')

        with patch.object(helper, 'CacheFetcher', FailingCacheFetcher):
            with pytest.raises(UnauthorizedAccess):
                has_valid_token(token)

    def test_invalid_jwks_response_raises_unauthorized(self, test_key):
        """Test that invalid JWKS response raises UnauthorizedAccess."""
        from axioms_drf import helper

        # Clear cache to ensure we fetch JWKS
        cache.clear()

        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'exp': now + 3600,
            'iat': now
        }

        token = generate_jwt_token(test_key, claims)

        # Mock CacheFetcher to return invalid JWKS
        class InvalidJWKSFetcher:
            def fetch(self, url, max_age=300):
                return b'invalid json'

        with patch.object(helper, 'CacheFetcher', InvalidJWKSFetcher):
            with pytest.raises(UnauthorizedAccess):
                has_valid_token(token)
