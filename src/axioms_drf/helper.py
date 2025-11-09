"""Token validation helpers for Axioms DRF.

This module provides helper functions for JWT token validation with support for
algorithm validation, issuer validation, and configuration hierarchy.
"""

import json
import ssl
import time
from urllib.request import urlopen

import jwt
from box import Box
from django.conf import settings
from django.core.cache import cache
from jwcrypto import jwk, jws

from .authentication import UnauthorizedAccess

# Allowed JWT algorithms (secure asymmetric algorithms only)
ALLOWED_ALGORITHMS = frozenset(
    [
        "RS256",
        "RS384",
        "RS512",  # RSA with SHA-256, SHA-384, SHA-512
        "ES256",
        "ES384",
        "ES512",  # ECDSA with SHA-256, SHA-384, SHA-512
        "PS256",
        "PS384",
        "PS512",  # RSA-PSS with SHA-256, SHA-384, SHA-512
    ]
)


def has_valid_token(token):
    """Validate JWT token with algorithm and issuer validation.

    Args:
        token: JWT token string.

    Returns:
        Box: Validated JWT payload.

    Raises:
        UnauthorizedAccess: If token is invalid.
    """
    # Get and validate the token header
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        raise UnauthorizedAccess

    # Validate algorithm
    alg = header.get("alg")
    if not alg or alg not in ALLOWED_ALGORITHMS:
        raise UnauthorizedAccess

    # Validate key ID presence
    kid = header.get("kid")
    if not kid:
        raise UnauthorizedAccess

    # Get public key from JWKS
    jwks_url = get_jwks_url()
    key = get_key_from_jwks_json(jwks_url, kid)

    # Validate token with algorithm check
    payload = check_token_validity(token, key, alg)
    if payload:
        return payload
    else:
        raise UnauthorizedAccess


def check_token_validity(token, key, alg):
    """Check token validity including expiry, audience, and issuer.

    Args:
        token: JWT token string.
        key: JWK key for verification.
        alg: Algorithm from token header.

    Returns:
        Box: Validated payload or False.
    """
    payload = get_payload_from_token(token, key, alg)
    if not payload:
        return False

    now = time.time()

    # Check expiry
    if now > payload.exp:
        return False

    # Check audience
    if settings.AXIOMS_AUDIENCE not in payload.aud:
        return False

    # Check issuer if configured
    expected_issuer = get_expected_issuer()
    if expected_issuer:
        token_issuer = getattr(payload, "iss", None)
        if not token_issuer:
            raise UnauthorizedAccess
        if token_issuer != expected_issuer:
            raise UnauthorizedAccess

    return payload


def get_payload_from_token(token, key, alg):
    """Extract and verify payload from JWT token.

    Args:
        token: JWT token string.
        key: JWK key for verification.
        alg: Expected algorithm.

    Returns:
        Box: Token payload or None.
    """
    jwstoken = jws.JWS()
    jwstoken.deserialize(token)

    # Verify algorithm matches
    token_alg = jwstoken.jose_header.get("alg")
    if token_alg != alg or token_alg not in ALLOWED_ALGORITHMS:
        return None

    try:
        jwstoken.verify(key)
        return Box(json.loads(jwstoken.payload))
    except jws.InvalidJWSSignature:
        return None


def get_expected_issuer():
    """Get expected issuer URL from settings.

    Returns issuer URL based on configuration hierarchy:
    1. AXIOMS_ISS_URL (if set)
    2. Constructed from AXIOMS_DOMAIN (if set)
    3. None (if neither is set, issuer validation is skipped)

    Returns:
        str or None: Expected issuer URL.
    """
    # Check for explicit issuer URL first
    if hasattr(settings, "AXIOMS_ISS_URL") and settings.AXIOMS_ISS_URL:
        return settings.AXIOMS_ISS_URL

    # Construct from domain if available
    if hasattr(settings, "AXIOMS_DOMAIN") and settings.AXIOMS_DOMAIN:
        domain = settings.AXIOMS_DOMAIN
        # Remove protocol if present
        domain = domain.replace("https://", "").replace("http://", "")
        return f"https://{domain}"

    # No issuer validation if neither is configured
    return None


def get_jwks_url():
    """Get JWKS URL from settings.

    Returns JWKS URL based on configuration hierarchy:
    1. AXIOMS_JWKS_URL (if explicitly set)
    2. Constructed from AXIOMS_ISS_URL (if set)
    3. Constructed from AXIOMS_DOMAIN (via issuer URL)

    Returns:
        str: JWKS URL.

    Raises:
        UnauthorizedAccess: If no valid configuration is found.
    """
    # Use explicit JWKS URL if provided
    if hasattr(settings, "AXIOMS_JWKS_URL") and settings.AXIOMS_JWKS_URL:
        return settings.AXIOMS_JWKS_URL

    # Construct from issuer URL
    issuer_url = get_expected_issuer()
    if issuer_url:
        return f"{issuer_url}/.well-known/jwks.json"

    # Fallback to legacy AXIOMS_DOMAIN (for backward compatibility)
    if hasattr(settings, "AXIOMS_DOMAIN") and settings.AXIOMS_DOMAIN:
        domain = settings.AXIOMS_DOMAIN
        domain = domain.replace("https://", "").replace("http://", "")
        return f"https://{domain}/.well-known/jwks.json"

    raise UnauthorizedAccess


def check_scopes(provided_scopes, required_scopes):
    """Check if any required scope is present in token scopes.

    Args:
        provided_scopes: Space-separated scope string from token.
        required_scopes: List of required scopes (OR logic - any one is sufficient).

    Returns:
        bool: True if at least one required scope is present.
    """
    if not required_scopes:
        return True

    token_scopes = set(provided_scopes.split())
    scopes = set(required_scopes)
    # Any one of the required scopes is sufficient (OR logic)
    return len(token_scopes.intersection(scopes)) > 0


def check_roles(token_roles, view_roles):
    """Check if any required role is present in token roles.

    Args:
        token_roles: List of roles from token.
        view_roles: List of required roles (OR logic - any one is sufficient).

    Returns:
        bool: True if at least one required role is present.
    """
    if not view_roles:
        return True

    token_roles = set(token_roles)
    view_roles = set(view_roles)
    # Any one of the required roles is sufficient (OR logic)
    return len(token_roles.intersection(view_roles)) > 0


def check_permissions(token_permissions, view_permissions):
    """Check if any required permission is present in token permissions.

    Args:
        token_permissions: List of permissions from token.
        view_permissions: List of required permissions (OR logic - any one is sufficient).

    Returns:
        bool: True if at least one required permission is present.
    """
    if not view_permissions:
        return True

    token_permissions = set(token_permissions)
    view_permissions = set(view_permissions)
    # Any one of the required permissions is sufficient (OR logic)
    return len(token_permissions.intersection(view_permissions)) > 0


def get_key_from_jwks_json(jwks_url, kid):
    """Retrieve public key from JWKS endpoint.

    Args:
        jwks_url: URL to JWKS endpoint.
        kid: Key ID to retrieve.

    Returns:
        JWK: Public key for verification.

    Raises:
        UnauthorizedAccess: If key cannot be retrieved.
    """
    fetcher = CacheFetcher()
    data = fetcher.fetch(jwks_url, 600)
    try:
        key = jwk.JWKSet().from_json(data).get_key(kid)
        return key
    except Exception:
        raise UnauthorizedAccess


class CacheFetcher:
    """Cache-enabled fetcher for JWKS data."""

    def fetch(self, url, max_age=300):
        """Fetch data from URL with caching.

        Args:
            url: URL to fetch.
            max_age: Cache timeout in seconds.

        Returns:
            bytes: Fetched data.
        """
        # Redis cache
        cached = cache.get("jwks" + url)
        if cached:
            return cached
        context = ssl._create_unverified_context()
        data = urlopen(url, context=context).read()
        cache.set("jwks" + url, data, timeout=max_age)
        return data
