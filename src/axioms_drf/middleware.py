"""Django middleware for JWT token extraction and validation.

This module provides middleware that extracts JWT tokens from the ``Authorization``
header and validates them before the request reaches the view. It sets attributes
on the request object that authentication classes use to determine access.

The middleware must be added to Django's ``MIDDLEWARE`` setting before the request
reaches any views that require authentication.

Configuration:
    Add to Django settings.py::

        MIDDLEWARE = [
            'axioms_drf.middleware.AccessTokenMiddleware',
            # ... other middleware
        ]

        # Required settings
        AXIOMS_AUDIENCE = 'your-api-audience'

        # Optional settings (one of these is required)
        AXIOMS_DOMAIN = 'your-auth-domain.com'
        AXIOMS_ISS_URL = 'https://your-auth-domain.com'
        AXIOMS_JWKS_URL = 'https://your-auth-domain.com/.well-known/jwks.json'

Classes:
    ``AccessTokenMiddleware``: Main middleware for JWT token processing.
"""

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

from .helper import has_valid_token


class AccessTokenMiddleware(MiddlewareMixin):
    """Middleware that extracts and validates JWT tokens from ``Authorization`` header.

    This middleware processes incoming requests to extract JWT tokens from the
    ``Authorization`` header, validates them, and sets request attributes that
    authentication classes use to grant or deny access.

    The middleware sets the following attributes on the request:
        ``auth_jwt`` (Box|False|None): Validated token payload as Box object, ``False`` if
                                       validation failed, ``None`` if no token provided.
        ``missing_auth_header`` (bool): ``True`` if ``Authorization`` header is missing.
        ``invalid_bearer_token`` (bool): ``True`` if Bearer format is invalid.

    Token validation includes:
        - Signature verification using JWKS
        - Expiration time check
        - Audience claim validation
        - Issuer claim validation (if configured)
        - Algorithm validation (only secure asymmetric algorithms allowed)

    The middleware catches all validation exceptions and sets ``auth_jwt=False``,
    allowing authentication classes to handle the error appropriately.

    Example::

        # In settings.py
        MIDDLEWARE = [
            'axioms_drf.middleware.AccessTokenMiddleware',
            'django.middleware.common.CommonMiddleware',
            # ... other middleware
        ]

        AXIOMS_AUDIENCE = 'my-api'
        AXIOMS_DOMAIN = 'auth.example.com'

    Raises:
        Exception: If required settings are not configured. ``AXIOMS_AUDIENCE`` is
            always required. At least one JWKS source must be configured:
            ``AXIOMS_JWKS_URL``, ``AXIOMS_ISS_URL``, or ``AXIOMS_DOMAIN``.

    Note:
        This middleware should be placed early in the middleware stack, before
        any authentication-dependent middleware.
    """

    def process_request(self, request):
        """Process incoming request to extract and validate JWT token.

        This method is called for every request before it reaches the view.
        It extracts the JWT token from the ``Authorization`` header, validates it,
        and sets request attributes for use by authentication classes.

        Request attributes set:
            ``auth_jwt``: Box object with token payload if valid, ``False`` if invalid,
                ``None`` if missing
            ``missing_auth_header``: ``True`` if ``Authorization`` header not present
            ``invalid_bearer_token``: ``True`` if header doesn't match
                ``Bearer <token>`` format

        Args:
            request: Django HttpRequest object.

        Raises:
            Exception: If ``AXIOMS_AUDIENCE`` is not configured or if none of the JWKS
                source settings (``AXIOMS_JWKS_URL``, ``AXIOMS_ISS_URL``, or
                ``AXIOMS_DOMAIN``) are configured.

        Returns:
            None: This method doesn't return anything, it modifies the request in-place.
        """
        header_name = "Authorization"
        token_prefix = "bearer"
        request.auth_jwt = None
        request.missing_auth_header = False
        request.invalid_bearer_token = False

        # Validate required settings
        if not hasattr(settings, "AXIOMS_AUDIENCE") or not settings.AXIOMS_AUDIENCE:
            raise Exception(
                "🔥🔥 AXIOMS_AUDIENCE is required. Please set AXIOMS_AUDIENCE in your settings."
            )

        # Validate that at least one JWKS source is configured
        has_jwks_url = hasattr(settings, "AXIOMS_JWKS_URL") and settings.AXIOMS_JWKS_URL
        has_iss_url = hasattr(settings, "AXIOMS_ISS_URL") and settings.AXIOMS_ISS_URL
        has_domain = hasattr(settings, "AXIOMS_DOMAIN") and settings.AXIOMS_DOMAIN

        if not (has_jwks_url or has_iss_url or has_domain):
            raise Exception(
                "🔥🔥 JWKS URL configuration required. Please set one of: "
                "AXIOMS_JWKS_URL, AXIOMS_ISS_URL, or AXIOMS_DOMAIN in your settings."
            )

        auth_header = request.headers.get(header_name, None)
        if auth_header is None:
            request.missing_auth_header = True
        else:
            try:
                bearer, _, token = auth_header.partition(" ")
                # Strip whitespace from token to handle multiple spaces
                token = token.strip()
                if bearer.lower() == token_prefix and token != "":
                    payload = has_valid_token(token)
                    request.auth_jwt = payload
                else:
                    request.invalid_bearer_token = True
            except Exception:
                # Catch all exceptions from token validation
                # (invalid algorithm, expired, wrong issuer, etc.)
                # Set auth_jwt to False so authentication classes know the token is invalid
                request.auth_jwt = False
