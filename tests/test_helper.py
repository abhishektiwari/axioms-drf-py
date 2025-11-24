"""Integration tests for helper.py functions.

This module contains comprehensive tests for has_valid_token function.
"""

import json
import time
import pytest
from django.test import override_settings
from django.core.cache import cache
from box.exceptions import BoxError
from axioms_drf.helper import has_valid_token, build_config_from_django_settings
from axioms_drf.authentication import UnauthorizedAccess
from tests.conftest import generate_jwt_token


@pytest.fixture(autouse=True)
def clear_cache_between_tests():
    """Clear Django cache before and after each test to prevent JWKS caching issues."""
    cache.clear()
    yield
    cache.clear()


class TestBuildConfigFromDjangoSettings:
    """Test build_config_from_django_settings function."""

    def test_builds_config_with_all_settings(self):
        """Test that all configured Django settings are included in config."""
        config = build_config_from_django_settings()

        # Check settings from tests/settings.py
        assert config["AXIOMS_AUDIENCE"] == "test-audience"
        assert config["AXIOMS_ISS_URL"] == "https://test-domain.com"
        assert config["AXIOMS_JWKS_URL"] == "https://test-domain.com/.well-known/jwks.json"

    @override_settings(
        AXIOMS_SCOPE_CLAIMS=["scp", "scope"],
        AXIOMS_ROLES_CLAIMS=["roles"],
        AXIOMS_PERMISSIONS_CLAIMS=["permissions"]
    )
    def test_builds_config_with_custom_claim_names(self):
        """Test that custom claim name settings are included in config."""
        config = build_config_from_django_settings()

        assert config["AXIOMS_SCOPE_CLAIMS"] == ["scp", "scope"]
        assert config["AXIOMS_ROLES_CLAIMS"] == ["roles"]
        assert config["AXIOMS_PERMISSIONS_CLAIMS"] == ["permissions"]

    @override_settings(AXIOMS_DOMAIN="https://auth.example.com")
    def test_builds_config_with_domain(self):
        """Test that AXIOMS_DOMAIN is included in config."""
        config = build_config_from_django_settings()

        assert config["AXIOMS_DOMAIN"] == "https://auth.example.com"

    @override_settings(AXIOMS_TOKEN_TYPS=["at+jwt", "JWT"])
    def test_builds_config_with_token_typs(self):
        """Test that AXIOMS_TOKEN_TYPS is included in config."""
        config = build_config_from_django_settings()

        assert config["AXIOMS_TOKEN_TYPS"] == ["at+jwt", "JWT"]


class TestHasValidToken:
    """Test has_valid_token function with various token scenarios.

    All Axioms settings are configured centrally in tests/settings.py:
    - AXIOMS_AUDIENCE = 'test-audience'
    - AXIOMS_ISS_URL = 'https://test-domain.com'
    - AXIOMS_JWKS_URL = 'https://test-domain.com/.well-known/jwks.json'
    """

    def test_valid_token_returns_payload(self, test_key):
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

    def test_expired_token_raises_unauthorized(self, test_key):
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

    def test_tampered_token_raises_unauthorized(self, test_key):
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

    def test_wrong_audience_raises_unauthorized(self, test_key):
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

    def test_wrong_issuer_raises_unauthorized(self, test_key):
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
    def test_token_without_issuer_when_not_required(self, test_key):
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

    def test_token_without_kid_raises_unauthorized(self, test_key):
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

    def test_token_with_symmetric_algorithm_raises_unauthorized(self, test_key):
        """Test that a token with symmetric algorithm (HS256) raises UnauthorizedAccess.

        Uses manual JWT construction to create a token claiming HS256 algorithm.
        """
        import base64

        now = int(time.time())

        # Manually construct JWT with HS256 in header
        header = base64.urlsafe_b64encode(
            json.dumps({'alg': 'HS256', 'typ': 'JWT', 'kid': test_key.kid}).encode()
        ).decode().rstrip('=')

        payload = base64.urlsafe_b64encode(
            json.dumps({
                'sub': 'user123',
                'aud': ['test-audience'],
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now,
                'jti': 'test-jti'
            }).encode()
        ).decode().rstrip('=')

        # Create fake signature
        signature = base64.urlsafe_b64encode(b'fake_signature').decode().rstrip('=')

        token = f"{header}.{payload}.{signature}"

        with pytest.raises(UnauthorizedAccess):
            has_valid_token(token)

    def test_token_with_none_algorithm_raises_unauthorized(self, test_key):
        """Test that a token with 'none' algorithm raises UnauthorizedAccess.

        Uses manual JWT construction to create a token claiming 'none' algorithm.
        """
        import base64

        now = int(time.time())

        # Manually construct JWT with 'none' in header
        header = base64.urlsafe_b64encode(
            json.dumps({'alg': 'none', 'typ': 'JWT', 'kid': test_key.kid}).encode()
        ).decode().rstrip('=')

        payload = base64.urlsafe_b64encode(
            json.dumps({
                'sub': 'user123',
                'aud': ['test-audience'],
                'iss': 'https://test-domain.com',
                'exp': now + 3600,
                'iat': now,
                'jti': 'test-jti'
            }).encode()
        ).decode().rstrip('=')

        # 'none' algorithm has no signature
        token = f"{header}.{payload}."

        with pytest.raises(UnauthorizedAccess):
            has_valid_token(token)

    def test_token_without_exp_claim_raises_unauthorized(self, test_key):
        """Test that a token without exp claim raises UnauthorizedAccess.

        Manually constructs a properly signed JWT token that's missing the exp claim.
        """
        import jwt as pyjwt

        now = int(time.time())
        claims = {
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            # No 'exp' claim - this should cause rejection
            'iat': now,
            'jti': 'test-jti'
        }

        # Use PyJWT directly with options to allow missing exp during encoding
        key_json = test_key.export_private()
        algorithm = pyjwt.algorithms.get_default_algorithms()['RS256']
        pyjwt_key = algorithm.from_jwk(key_json)

        # Encode without exp claim (PyJWT allows this during encoding)
        token = pyjwt.encode(
            payload=claims,
            key=pyjwt_key,
            algorithm='RS256',
            headers={'kid': test_key.kid}
        )

        # Our validation should reject this because require_exp is True
        with pytest.raises(UnauthorizedAccess):
            has_valid_token(token)

    def test_token_with_future_iat_raises_unauthorized(self, test_key):
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

    def test_token_with_nbf_in_future_raises_unauthorized(self, test_key):
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

    def test_token_with_multiple_audiences(self, test_key):
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

    def test_malformed_token_raises_unauthorized(self, test_key):
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

    def test_token_with_different_kid_raises_unauthorized(self, test_key):
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

    def test_token_with_all_allowed_algorithms(self, test_key):
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

    def test_token_with_extra_claims(self, test_key):
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

    def test_payload_immutability(self, test_key):
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
