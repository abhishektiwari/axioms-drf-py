"""Token validation helpers for Axioms DRF.

This module provides helper functions for JWT token validation with support for
algorithm validation, issuer validation, and configuration hierarchy.
"""

import logging
import ssl
from urllib.request import urlopen

import jwt
from box import Box
from django.conf import settings
from django.core.cache import cache
from jwcrypto import jwk

from .authentication import UnauthorizedAccess

logger = logging.getLogger(__name__)

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
        Box: Immutable (frozen) Box containing validated JWT payload. The returned Box
             cannot be modified to prevent tampering with validated token claims.

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
    try:
        payload = check_token_validity(token, key, alg)
        return payload
    except UnauthorizedAccess:
        # Re-raise authentication errors from token validation
        raise


def check_token_validity(token, key, alg):
    """Check token validity including expiry, audience, and issuer.

    Args:
        token: JWT token string.
        key: JWK key for verification.
        alg: Algorithm from token header (already validated against ALLOWED_ALGORITHMS).

    Returns:
        Box: Immutable (frozen) Box containing validated payload. The returned Box
             cannot be modified to prevent tampering with validated token claims.

    Raises:
        UnauthorizedAccess: If token validation fails.
    """
    try:
        # Convert JWK to PyJWT-compatible key
        key_json = key.export_public()
        algorithm = jwt.algorithms.get_default_algorithms()[alg]
        pyjwt_key = algorithm.from_jwk(key_json)

        # Build decode options
        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_aud": True,
            "verify_iss": False,  # We'll handle this conditionally
            "verify_iat": True,
            "verify_nbf": True,
            "require_exp": True,
        }

        # Get expected issuer if configured
        expected_issuer = get_expected_issuer()
        if expected_issuer:
            options["verify_iss"] = True

        # Decode and verify token
        # Use ALLOWED_ALGORITHMS for defense-in-depth against algorithm confusion attacks
        payload = jwt.decode(
            token,
            pyjwt_key,
            algorithms=list(ALLOWED_ALGORITHMS),
            audience=settings.AXIOMS_AUDIENCE,
            issuer=expected_issuer,
            options=options,
        )

        # Explicitly verify exp claim exists (PyJWT 2.10.1 bug workaround)
        # See: https://github.com/jpadilla/pyjwt/issues/870
        if "exp" not in payload:
            raise UnauthorizedAccess

        # Return immutable Box to prevent payload modification
        return Box(payload, frozen_box=True)

    except jwt.ExpiredSignatureError:
        raise UnauthorizedAccess
    except jwt.InvalidAudienceError:
        raise UnauthorizedAccess
    except jwt.InvalidIssuerError:
        raise UnauthorizedAccess
    except jwt.InvalidSignatureError:
        raise UnauthorizedAccess
    except jwt.DecodeError:
        raise UnauthorizedAccess
    except jwt.InvalidTokenError:
        raise UnauthorizedAccess
    except Exception:
        raise UnauthorizedAccess


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


def get_token_scopes(auth_jwt):
    """Extract scopes from token using standard or configured claim names.

    Checks the ``scope`` claim first, then any custom claims configured in
    ``AXIOMS_SCOPE_CLAIMS`` setting. Supports both string and list formats.

    Args:
        auth_jwt: Authenticated JWT token payload (Box object).

    Returns:
        str: Space-separated scope string from token, or empty string if not found.

    Example::

        # Standard scope claim
        token = {'scope': 'read:data write:data'}
        scopes = get_token_scopes(token)  # Returns: 'read:data write:data'

        # Custom scope claim (list format)
        token = {'scp': ['read:data', 'write:data']}
        scopes = get_token_scopes(token)  # Returns: 'read:data write:data'
    """
    # Try standard 'scope' claim first
    if hasattr(auth_jwt, "scope"):
        return getattr(auth_jwt, "scope", "")

    # Then try configured claims if AXIOMS_SCOPE_CLAIMS is set
    if hasattr(settings, "AXIOMS_SCOPE_CLAIMS"):
        for claim_name in settings.AXIOMS_SCOPE_CLAIMS:
            if hasattr(auth_jwt, claim_name):
                scope_value = getattr(auth_jwt, claim_name, "")
                # Handle both string and list/tuple formats
                # Note: Frozen Box converts lists to tuples for immutability
                if isinstance(scope_value, (list, tuple)):
                    return " ".join(scope_value)
                return scope_value

    return ""


def get_token_roles(auth_jwt):
    """Extract roles from token using standard or configured claim names.

    Checks the ``roles`` claim first, then any custom claims configured in
    ``AXIOMS_ROLES_CLAIMS`` setting.

    Args:
        auth_jwt: Authenticated JWT token payload (Box object).

    Returns:
        list: List of roles from token, or empty list if not found.

    Example::

        # Standard roles claim
        token = {'roles': ['admin', 'editor']}
        roles = get_token_roles(token)  # Returns: ['admin', 'editor']

        # Custom namespaced roles claim
        token = {'https://example.com/roles': ['admin']}
        roles = get_token_roles(token)  # Returns: ['admin']
    """
    # Try standard 'roles' claim first
    if hasattr(auth_jwt, "roles"):
        return getattr(auth_jwt, "roles", [])

    # Then try configured claims if AXIOMS_ROLES_CLAIMS is set
    if hasattr(settings, "AXIOMS_ROLES_CLAIMS"):
        for claim_name in settings.AXIOMS_ROLES_CLAIMS:
            if hasattr(auth_jwt, claim_name):
                return getattr(auth_jwt, claim_name, [])

    return []


def get_token_permissions(auth_jwt):
    """Extract permissions from token using standard or configured claim names.

    Checks the ``permissions`` claim first, then any custom claims configured in
    ``AXIOMS_PERMISSIONS_CLAIMS`` setting.

    Args:
        auth_jwt: Authenticated JWT token payload (Box object).

    Returns:
        list: List of permissions from token, or empty list if not found.

    Example::

        # Standard permissions claim
        token = {'permissions': ['read:users', 'write:users']}
        perms = get_token_permissions(token)  # Returns: ['read:users', 'write:users']

        # Custom namespaced permissions claim
        token = {'https://example.com/permissions': ['read:users']}
        perms = get_token_permissions(token)  # Returns: ['read:users']
    """
    # Try standard 'permissions' claim first
    if hasattr(auth_jwt, "permissions"):
        return getattr(auth_jwt, "permissions", [])

    # Then try configured claims if AXIOMS_PERMISSIONS_CLAIMS is set
    if hasattr(settings, "AXIOMS_PERMISSIONS_CLAIMS"):
        for claim_name in settings.AXIOMS_PERMISSIONS_CLAIMS:
            if hasattr(auth_jwt, claim_name):
                return getattr(auth_jwt, claim_name, [])

    return []


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
    try:
        fetcher = CacheFetcher()
        data = fetcher.fetch(jwks_url, 600)
        key = jwk.JWKSet().from_json(data).get_key(kid)
        return key
    except Exception:
        # Catch all errors: network errors, HTTP errors, invalid JWKS, missing key, etc.
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

        Raises:
            Exception: If URL cannot be fetched (network error, HTTP error, timeout, etc.).
        """
        # Check cache first
        cached = cache.get("jwks" + url)
        if cached:
            return cached

        # Fetch from URL with SSL context
        try:
            context = ssl._create_unverified_context()
            data = urlopen(url, context=context).read()
            cache.set("jwks" + url, data, timeout=max_age)
            return data
        except Exception as e:
            # Log the error with details for debugging
            logger.error(
                f"Failed to fetch JWKS from {url}: {type(e).__name__}: {str(e)}"
            )
            # Re-raise to bubble up to middleware
            raise
