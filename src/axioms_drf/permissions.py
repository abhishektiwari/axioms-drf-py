"""Django REST Framework permission classes for JWT claim-based authorization.

This module provides permission classes that perform authorization based on claims
in validated JWT tokens (scopes, roles, permissions). These classes work with the
authentication classes and middleware to provide fine-grained access control.

Permission Logic:
    Each permission class supports both OR and AND logic through different attributes:
    - ``_any_`` attributes: User needs ANY ONE of the specified claims (OR logic)
    - ``_all_`` attributes: User needs ALL of the specified claims (AND logic)

Configuration:
    Configure custom claim names in Django settings::

        # Optional: Configure custom claim names for roles
        AXIOMS_ROLES_CLAIMS = ['roles', 'https://example.com/claims/roles']

        # Optional: Configure custom claim names for permissions
        AXIOMS_PERMISSIONS_CLAIMS = ['permissions', 'https://example.com/claims/permissions']

        # Optional: Configure custom claim names for scopes
        AXIOMS_SCOPE_CLAIMS = ['scope', 'scp']

Classes:
    ``HasAccessTokenScopes``: Check scopes (supports both OR and AND logic).
    ``HasAccessTokenRoles``: Check roles (supports both OR and AND logic).
    ``HasAccessTokenPermissions``: Check permissions (supports both OR and AND logic).
    ``InsufficientPermission``: Exception raised when authorization fails.

Example::

    from rest_framework.views import APIView
    from rest_framework.response import Response
    from axioms_drf.authentication import HasValidAccessToken
    from axioms_drf.permissions import HasAccessTokenScopes, HasAccessTokenRoles

    # OR logic - user needs ANY ONE scope
    class DataView(APIView):
        authentication_classes = [HasValidAccessToken]
        permission_classes = [HasAccessTokenScopes]
        access_token_scopes = ['read:data', 'write:data']  # OR logic (backward compatible)
        # OR use: access_token_any_scopes = ['read:data', 'write:data']

        def get(self, request):
            return Response({'data': 'protected'})

    # AND logic - user needs ALL scopes
    class SecureView(APIView):
        authentication_classes = [HasValidAccessToken]
        permission_classes = [HasAccessTokenScopes]
        access_token_all_scopes = ['read:data', 'write:data']  # AND logic

        def post(self, request):
            return Response({'status': 'created'})
"""

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.permissions import BasePermission

from .helper import check_permissions, check_roles, check_scopes


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
                # Handle both string and list formats
                if isinstance(scope_value, list):
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


class HasAccessTokenScopes(BasePermission):
    """Permission class that checks if user has required scopes.

    Supports both OR logic (any scope) and AND logic (all scopes) through different
    view attributes:

    - ``access_token_scopes`` or ``access_token_any_scopes``: User needs ANY ONE
      (OR logic)
    - ``access_token_all_scopes``: User needs ALL (AND logic)

    Attributes:
        access_token_scopes: List of scopes (OR logic, backward compatible).
        access_token_any_scopes: List of scopes (OR logic, explicit).
        access_token_all_scopes: List of scopes (AND logic).

    Example::

        # OR logic - user needs read OR write
        class DataView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [HasAccessTokenScopes]
            access_token_scopes = ['read:data', 'write:data']

        # AND logic - user needs BOTH read AND write
        class SecureView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [HasAccessTokenScopes]
            access_token_all_scopes = ['read:data', 'write:data']

        # Method-level scopes - different scopes for each HTTP method
        class MethodLevelView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [HasAccessTokenScopes]

            @property
            def access_token_scopes(self):
                method_scopes = {
                    'GET': ['read:data'],
                    'POST': ['write:data'],
                    'DELETE': ['delete:data']
                }
                return method_scopes[self.request.method]

            def get(self, request):
                return Response({'data': []})

            def post(self, request):
                return Response({'status': 'created'})

    Raises:
        InsufficientPermission: If user doesn't have required scopes.
        ImproperlyConfigured: If no scope attribute is defined on the view.
    """

    message = "Permission Denied"

    def has_permission(self, request, view):
        """Check if user has required scopes.

        Args:
            request: Django REST Framework request with ``auth_jwt`` attribute.
            view: View instance with scope attributes.

        Returns:
            bool: ``True`` if user has required scopes.

        Raises:
            InsufficientPermission: If authorization fails.
        """
        try:
            auth_jwt = request.auth_jwt
            token_scopes = get_token_scopes(auth_jwt)

            # Get all scope requirements
            all_scopes = getattr(view, "access_token_all_scopes", None)
            any_scopes = getattr(view, "access_token_any_scopes", None) or getattr(
                view, "access_token_scopes", None
            )

            # At least one requirement must be defined
            if not all_scopes and not any_scopes:
                raise ImproperlyConfigured(
                    "Define access_token_scopes, access_token_any_scopes, "
                    "or access_token_all_scopes attribute"
                )

            # Check AND logic (all scopes required) if specified
            if all_scopes:
                if not token_scopes:
                    raise InsufficientPermission
                token_scopes_set = set(token_scopes.split())
                required_scopes_set = set(all_scopes)
                if not required_scopes_set.issubset(token_scopes_set):
                    raise InsufficientPermission

            # Check OR logic (any scope sufficient) if specified
            if any_scopes:
                if not token_scopes or not check_scopes(token_scopes, any_scopes):
                    raise InsufficientPermission

            # All checks passed
            return True

        except AttributeError:
            raise InsufficientPermission


class HasAccessTokenRoles(BasePermission):
    """Permission class that checks if user has required roles.

    Supports both OR logic (any role) and AND logic (all roles) through different
    view attributes:

    - ``access_token_roles`` or ``access_token_any_roles``: User needs ANY ONE
      (OR logic)
    - ``access_token_all_roles``: User needs ALL (AND logic)

    Attributes:
        access_token_roles: List of roles (OR logic, backward compatible).
        access_token_any_roles: List of roles (OR logic, explicit).
        access_token_all_roles: List of roles (AND logic).

    Example::

        # OR logic - user needs admin OR moderator
        class AdminView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [HasAccessTokenRoles]
            access_token_roles = ['admin', 'moderator']

        # AND logic - user needs BOTH admin AND superuser
        class SuperAdminView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [HasAccessTokenRoles]
            access_token_all_roles = ['admin', 'superuser']

        # Method-level roles - different roles for each HTTP method
        class MethodLevelView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [HasAccessTokenRoles]

            @property
            def access_token_roles(self):
                method_roles = {
                    'GET': ['viewer', 'editor'],
                    'POST': ['editor', 'admin'],
                    'DELETE': ['admin']
                }
                return method_roles[self.request.method]

            def get(self, request):
                return Response({'data': []})

            def post(self, request):
                return Response({'status': 'created'})

    Raises:
        InsufficientPermission: If user doesn't have required roles.
        ImproperlyConfigured: If no role attribute is defined on the view.
    """

    message = "Permission Denied"

    def has_permission(self, request, view):
        """Check if user has required roles.

        Args:
            request: Django REST Framework request with ``auth_jwt`` attribute.
            view: View instance with role attributes.

        Returns:
            bool: ``True`` if user has required roles.

        Raises:
            InsufficientPermission: If authorization fails.
        """
        try:
            auth_jwt = request.auth_jwt
            token_roles = get_token_roles(auth_jwt)

            # Get all role requirements
            all_roles = getattr(view, "access_token_all_roles", None)
            any_roles = getattr(view, "access_token_any_roles", None) or getattr(
                view, "access_token_roles", None
            )

            # At least one requirement must be defined
            if not all_roles and not any_roles:
                raise ImproperlyConfigured(
                    "Define access_token_roles, access_token_any_roles, "
                    "or access_token_all_roles attribute"
                )

            # Check AND logic (all roles required) if specified
            if all_roles:
                if not token_roles:
                    raise InsufficientPermission
                token_roles_set = set(token_roles)
                required_roles_set = set(all_roles)
                if not required_roles_set.issubset(token_roles_set):
                    raise InsufficientPermission

            # Check OR logic (any role sufficient) if specified
            if any_roles:
                if not check_roles(token_roles, any_roles):
                    raise InsufficientPermission

            # All checks passed
            return True

        except AttributeError:
            raise InsufficientPermission


class HasAccessTokenPermissions(BasePermission):
    """Permission class that checks if user has required permissions.

    Supports both OR logic (any permission) and AND logic (all permissions)
    through different view attributes:

    - ``access_token_permissions`` or ``access_token_any_permissions``:
      User needs ANY ONE (OR logic)
    - ``access_token_all_permissions``: User needs ALL (AND logic)

    Attributes:
        access_token_permissions: List of permissions (OR logic, backward compatible).
        access_token_any_permissions: List of permissions (OR logic, explicit).
        access_token_all_permissions: List of permissions (AND logic).

    Example::

        # OR logic - user needs read OR admin permission
        class UserView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [HasAccessTokenPermissions]
            access_token_permissions = ['user:read', 'user:admin']

        # AND logic - user needs BOTH write AND delete
        class CriticalView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [HasAccessTokenPermissions]
            access_token_all_permissions = ['user:write', 'user:delete']

        # Method-level permissions - different permission for each HTTP method
        class MethodLevelView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [HasAccessTokenPermissions]

            @property
            def access_token_permissions(self):
                method_permissions = {
                    'GET': ['user:read'],
                    'POST': ['user:create'],
                    'PATCH': ['user:update'],
                    'DELETE': ['user:delete']
                }
                return method_permissions[self.request.method]

            def get(self, request):
                return Response({'message': 'User read.'})

            def post(self, request):
                return Response({'message': 'User created.'})

    Raises:
        InsufficientPermission: If user doesn't have required permissions.
        ImproperlyConfigured: If no permission attribute is defined on the view.
    """

    message = "Permission Denied"

    def has_permission(self, request, view):
        """Check if user has required permissions.

        Args:
            request: Django REST Framework request with ``auth_jwt`` attribute.
            view: View instance with permission attributes.

        Returns:
            bool: ``True`` if user has required permissions.

        Raises:
            InsufficientPermission: If authorization fails.
        """
        try:
            auth_jwt = request.auth_jwt
            token_permissions = get_token_permissions(auth_jwt)

            # Get all permission requirements
            all_permissions = getattr(view, "access_token_all_permissions", None)
            any_permissions = getattr(
                view, "access_token_any_permissions", None
            ) or getattr(view, "access_token_permissions", None)

            # At least one requirement must be defined
            if not all_permissions and not any_permissions:
                raise ImproperlyConfigured(
                    "Define access_token_permissions, access_token_any_permissions, "
                    "or access_token_all_permissions attribute"
                )

            # Check AND logic (all permissions required) if specified
            if all_permissions:
                if not token_permissions:
                    raise InsufficientPermission
                token_perms_set = set(token_permissions)
                required_perms_set = set(all_permissions)
                if not required_perms_set.issubset(token_perms_set):
                    raise InsufficientPermission

            # Check OR logic (any permission sufficient) if specified
            if any_permissions:
                if not check_permissions(token_permissions, any_permissions):
                    raise InsufficientPermission

            # All checks passed
            return True

        except AttributeError:
            raise InsufficientPermission


class InsufficientPermission(APIException):
    """Exception raised when user lacks required scopes, roles, or permissions.

    This exception is raised by permission classes when a user's JWT token
    doesn't contain the required claims for accessing a protected endpoint.

    Attributes:
        status_code: HTTP 403 Forbidden
        default_detail: Error message dict with error flag and description
        default_code: ``insufficient_permission``

    Example::

        # Automatically raised by permission classes
        class ProtectedView(APIView):
            permission_classes = [HasAccessTokenScopes]
            access_token_scopes = ['admin']

            def get(self, request):
                # InsufficientPermission raised if user lacks 'admin' scope
                return Response({'data': 'protected'})
    """

    status_code = status.HTTP_403_FORBIDDEN
    default_detail = {
        "error": True,
        "message": "Insufficient role, scope or permission",
    }
    default_code = "insufficient_permission"
