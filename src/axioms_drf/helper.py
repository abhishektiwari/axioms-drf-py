"""Token validation helpers for Axioms DRF.

This module provides helper functions for JWT token validation with support for
algorithm validation, issuer validation, and configuration hierarchy.
"""

import logging

from axioms_core import (
    AxiomsError,
    check_token_validity,
    get_expected_issuer,
    get_key_from_jwks_json,
    validate_token_header,
)
from django.conf import settings

from .authentication import UnauthorizedAccess

logger = logging.getLogger(__name__)


def build_config_from_django_settings():
    """Build configuration dict from Django settings for axioms-core-py.

    Returns:
        dict: Configuration dictionary compatible with axioms-core-py.
    """
    config = {}

    if hasattr(settings, "AXIOMS_AUDIENCE"):
        config["AXIOMS_AUDIENCE"] = settings.AXIOMS_AUDIENCE
    if hasattr(settings, "AXIOMS_DOMAIN"):
        config["AXIOMS_DOMAIN"] = settings.AXIOMS_DOMAIN
    if hasattr(settings, "AXIOMS_ISS_URL"):
        config["AXIOMS_ISS_URL"] = settings.AXIOMS_ISS_URL
    if hasattr(settings, "AXIOMS_JWKS_URL"):
        config["AXIOMS_JWKS_URL"] = settings.AXIOMS_JWKS_URL
    if hasattr(settings, "AXIOMS_TOKEN_TYPS"):
        config["AXIOMS_TOKEN_TYPS"] = settings.AXIOMS_TOKEN_TYPS
    if hasattr(settings, "AXIOMS_SCOPE_CLAIMS"):
        config["AXIOMS_SCOPE_CLAIMS"] = settings.AXIOMS_SCOPE_CLAIMS
    if hasattr(settings, "AXIOMS_ROLES_CLAIMS"):
        config["AXIOMS_ROLES_CLAIMS"] = settings.AXIOMS_ROLES_CLAIMS
    if hasattr(settings, "AXIOMS_PERMISSIONS_CLAIMS"):
        config["AXIOMS_PERMISSIONS_CLAIMS"] = settings.AXIOMS_PERMISSIONS_CLAIMS

    return config


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
    config = build_config_from_django_settings()

    try:
        # Validate token header (alg, kid, typ) - raises AxiomsError on failure
        header = validate_token_header(token)

        # Get public key from JWKS
        kid = header.get("kid")
        key = get_key_from_jwks_json(kid, config)

        # Get expected values
        audience = getattr(settings, "AXIOMS_AUDIENCE", None)
        expected_issuer = get_expected_issuer(config)

        # Validate token (raises AxiomsError on failure)
        payload = check_token_validity(
            token=token,
            key=key,
            alg=header.get("alg"),
            audience=audience,
            issuer=expected_issuer,
        )

        return payload

    except AxiomsError:
        # Convert axioms-core-py AxiomsError to DRF UnauthorizedAccess
        raise UnauthorizedAccess
