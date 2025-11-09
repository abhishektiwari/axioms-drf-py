"""Django REST Framework authentication classes for JWT token validation.

This module provides authentication classes that integrate with Django REST Framework
to validate OAuth2/OIDC JWT access tokens. It works in conjunction with the
``AccessTokenMiddleware`` to perform token validation.

Classes:
    ``HasValidAccessToken``: Main authentication class requiring valid JWT token.
    ``IsAccessTokenAuthenticated``: Alias for ``HasValidAccessToken``.
    ``IsAnyPostOrIsAccessTokenAuthenticated``: Allows POST without authentication.
    ``IsAnyGetOrIsAccessTokenAuthenticated``: Allows GET without authentication.
    ``MissingAuthorizationHeader``: Exception for missing Authorization header.
    ``InvalidAuthorizationBearer``: Exception for invalid Bearer token format.
    ``UnauthorizedAccess``: Exception for invalid or expired tokens.

Example::

    from rest_framework.views import APIView
    from rest_framework.response import Response
    from axioms_drf.authentication import HasValidAccessToken

    class ProtectedView(APIView):
        authentication_classes = [HasValidAccessToken]

        def get(self, request):
            # User is authenticated with valid JWT token
            return Response({'user': request.user})
"""

from rest_framework import authentication
from rest_framework.exceptions import APIException
from django.conf import settings
from rest_framework import status


class HasValidAccessToken(authentication.BaseAuthentication):
    """Authentication class that validates JWT access tokens.

    This class integrates with ``AccessTokenMiddleware`` which performs the actual
    token validation. The middleware sets ``request.auth_jwt`` with the validated
    token payload, or flags for missing/invalid tokens.

    The authentication succeeds when:
    - A valid JWT token is present in the ``Authorization`` header
    - The token has not expired
    - The token has valid signature and claims
    - The token audience matches configured ``AXIOMS_AUDIENCE``

    ``OPTIONS`` requests are always allowed without authentication to support CORS preflight.

    Raises:
        MissingAuthorizationHeader: If ``Authorization`` header is not present.
        InvalidAuthorizationBearer: If Bearer token format is invalid.
        UnauthorizedAccess: If token is invalid, expired, or has invalid signature.

    Returns:
        tuple: (user_identifier, auth_success) where user_identifier is the ``sub`` claim.
    """

    def authenticate(self, request):
        """Authenticate the request using JWT token from middleware.

        Args:
            request: Django REST Framework request object with ``auth_jwt`` attribute
                    set by ``AccessTokenMiddleware``.

        Returns:
            tuple: ``(user_identifier, True)`` if authentication succeeds, where
                  ``user_identifier`` is the subject claim from the token.
            None: If no authentication is required (``OPTIONS`` request).

        Raises:
            MissingAuthorizationHeader: If ``Authorization`` header is missing.
            InvalidAuthorizationBearer: If Bearer format is invalid.
            UnauthorizedAccess: If token validation fails.
        """
        # Allow OPTIONS request without access token
        if request.method == 'OPTIONS':
            return (None, True)
        auth_jwt = request.auth_jwt
        missing_auth_header = request.missing_auth_header
        invalid_bearer_token = request.invalid_bearer_token
        if missing_auth_header is True:
            raise MissingAuthorizationHeader
        if invalid_bearer_token is True:
            raise InvalidAuthorizationBearer
        if auth_jwt is False:
            raise UnauthorizedAccess
        else:
            if auth_jwt.sub:
                return (auth_jwt.sub, True)
            else:
                raise UnauthorizedAccess
        return (None, False)

    def authenticate_header(self, request):
        """Return the ``WWW-Authenticate`` header value for 401 responses.

        Args:
            request: Django REST Framework request object.

        Returns:
            str: ``WWW-Authenticate`` header value following RFC 6750.
        """
        return "Bearer realm='{}', error='unauthorized_access', error_description='Invalid access token'".format(
            settings.AXIOMS_DOMAIN
        )


class IsAccessTokenAuthenticated(HasValidAccessToken):
    """Alias for ``HasValidAccessToken``.

    This class provides the same functionality as ``HasValidAccessToken``.
    Use this if you prefer the naming style.
    """

    def authenticate(self, request):
        """Authenticate using parent class implementation.

        Args:
            request: Django REST Framework request object.

        Returns:
            tuple: Same as ``HasValidAccessToken.authenticate()``.
        """
        super().authenticate(request)


class IsAnyPostOrIsAccessTokenAuthenticated(HasValidAccessToken):
    """Authentication class that allows ``POST`` requests without authentication.

    Useful for public endpoints that accept unauthenticated ``POST`` requests
    (e.g., user registration, password reset) but require authentication
    for other methods.

    Example::

        class RegisterView(APIView):
            authentication_classes = [IsAnyPostOrIsAccessTokenAuthenticated]

            def post(self, request):
                # Anyone can register (no auth required)
                return Response({'status': 'registered'})

            def get(self, request):
                # Requires valid JWT token
                return Response({'user': request.user})
    """

    def authenticate(self, request):
        """Authenticate request, allowing ``POST`` without token.

        Args:
            request: Django REST Framework request object.

        Returns:
            tuple: ``(None, True)`` for ``POST`` requests, otherwise delegates to parent.
        """
        # Allow POST requests without access token
        if request.method == 'POST':
            return (None, True)
        else:
            super().authenticate(request)


class IsAnyGetOrIsAccessTokenAuthenticated(HasValidAccessToken):
    """Authentication class that allows ``GET`` requests without authentication.

    Useful for public read endpoints that don't require authentication
    for viewing but require authentication for modifications.

    Example::

        class ArticleView(APIView):
            authentication_classes = [IsAnyGetOrIsAccessTokenAuthenticated]

            def get(self, request):
                # Anyone can read articles (no auth required)
                return Response({'articles': []})

            def post(self, request):
                # Requires valid JWT token to create
                return Response({'status': 'created'})
    """

    def authenticate(self, request):
        """Authenticate request, allowing ``GET`` without token.

        Args:
            request: Django REST Framework request object.

        Returns:
            tuple: ``(None, True)`` for ``GET`` requests, otherwise delegates to parent.
        """
        # Allow GET requests without access token
        if request.method == 'GET':
            return (None, True)
        else:
            super().authenticate(request)


class MissingAuthorizationHeader(APIException):
    """Exception raised when ``Authorization`` header is missing from request.

    This exception is raised when a protected endpoint is accessed without
    providing the ``Authorization`` header.

    Attributes:
        status_code: HTTP 401 Unauthorized
        default_detail: Error message dict with error flag and description
        default_code: ``missing_header``
    """
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = {"error": True, "message": "Missing Authorization Header"}
    default_code = "missing_header"


class InvalidAuthorizationBearer(APIException):
    """Exception raised when Bearer token format is invalid.

    This exception is raised when the ``Authorization`` header is present but
    doesn't follow the ``Bearer <token>`` format.

    Attributes:
        status_code: HTTP 401 Unauthorized
        default_detail: Error message dict with error flag and description
        default_code: ``missing_bearer``
    """
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = {"error": True, "message": "Invalid Authorization Bearer"}
    default_code = "missing_bearer"


class UnauthorizedAccess(APIException):
    """Exception raised when JWT token validation fails.

    This exception is raised when:
    - Token signature is invalid
    - Token has expired
    - Token audience doesn't match configured ``AXIOMS_AUDIENCE``
    - Token issuer doesn't match configured ``AXIOMS_ISS_URL``
    - Token algorithm is not in ``ALLOWED_ALGORITHMS``
    - Token is missing required claims

    Attributes:
        status_code: HTTP 401 Unauthorized
        default_detail: Error message dict with error flag and description
        default_code: ``unauthorized_access``
    """
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = {"error": True, "message": "Invalid access token."}
    default_code = "unauthorized_access"
