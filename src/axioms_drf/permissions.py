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
    - ``HasAccessTokenScopes``: Check scopes (supports both OR and AND logic).
    - ``HasAccessTokenRoles``: Check roles (supports both OR and AND logic).
    - ``HasAccessTokenPermissions``: Check permissions (supports both OR and AND logic).
    - ``IsSubOwner``: Object-level permission for token subject ownership.
    - ``IsSubOwnerOrSafeOnly``: Object-level permission allowing safe methods or owner access.
    - ``IsSafeOnly``: Permission allowing only safe HTTP methods.
    - ``InsufficientPermission``: Exception raised when authorization fails.

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

from django.core.exceptions import ImproperlyConfigured
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.permissions import BasePermission

from .helper import (
    check_permissions,
    check_roles,
    check_scopes,
    get_token_permissions,
    get_token_roles,
    get_token_scopes,
)


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


class IsSubOwner(BasePermission):
    """Object-level permission that checks if the token subject matches the object owner.

    This permission class checks if the ``sub`` (subject) claim from the JWT token
    matches a specified attribute on the object being accessed. This is useful for
    ensuring users can only access their own resources.

    Attributes:
        owner_attribute: Name of the object attribute to compare with token ``sub``.
                        Defaults to ``'user'``.

    Example::

        # Basic usage - compares token sub with object.owner
        class ArticleDetailView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [IsSubOwner]
            owner_attribute = 'author_id'  # Compare with object.author_id

            def get_object(self):
                return Article.objects.get(pk=self.kwargs['pk'])

            def get(self, request, pk):
                article = self.get_object()
                self.check_object_permissions(request, article)
                return Response({'title': article.title})

        # Using with ViewSet
        class ArticleViewSet(viewsets.ModelViewSet):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [IsSubOwner]
            owner_attribute = 'user_id'
            queryset = Article.objects.all()
            serializer_class = ArticleSerializer

    Raises:
        InsufficientPermission: If token subject doesn't match object owner.
        ImproperlyConfigured: If ``owner_attribute`` is not defined.
    """

    message = "Permission Denied - Not the owner"

    def has_object_permission(self, request, view, obj):
        """Check if token subject matches object owner attribute.

        Args:
            request: Django REST Framework request with ``auth_jwt`` attribute.
            view: View instance with ``owner_attribute``.
            obj: Object being accessed.

        Returns:
            bool: ``True`` if token subject matches object owner.

        Raises:
            InsufficientPermission: If authorization fails.
            ImproperlyConfigured: If owner_attribute is not set or object doesn't
                have the attribute.
        """
        try:
            auth_jwt = request.auth_jwt
            token_sub = getattr(auth_jwt, "sub", None)

            if not token_sub:
                raise InsufficientPermission

            # Get the owner attribute name from view
            owner_attr = getattr(view, "owner_attribute", None)

            # Warn if owner_attribute is not explicitly set
            if owner_attr is None:
                import warnings

                warnings.warn(
                    f"{view.__class__.__name__} does not explicitly set 'owner_attribute'. "
                    f"Defaulting to 'user'. This may cause ImproperlyConfigured errors. "
                    f"Set owner_attribute on your view to the correct field name "
                    f"(e.g., owner_attribute = 'author_sub').",
                    UserWarning,
                    stacklevel=2,
                )
                owner_attr = "user"

            if not hasattr(obj, owner_attr):
                raise ImproperlyConfigured(
                    f"Object does not have attribute '{owner_attr}'. "
                    f"Set owner_attribute on the view to the correct field name."
                )

            # Get the owner value from object
            owner_value = getattr(obj, owner_attr, None)

            # Compare token sub with object owner
            if str(token_sub) != str(owner_value):
                raise InsufficientPermission

            return True

        except AttributeError:
            raise InsufficientPermission


class IsSubOwnerOrSafeOnly(BasePermission):
    """Object-level permission for safe methods or owner-only modifications.

    Allows safe HTTP methods (GET, HEAD, OPTIONS by default) for all authenticated
    users, but restricts unsafe methods (POST, PUT, PATCH, DELETE) to the object owner.
    Owner is determined by comparing the token ``sub`` claim with a specified object
    attribute.

    Attributes:
        owner_attribute: Name of the object attribute to compare with token ``sub``.
                        Defaults to ``'owner'``.
        safe_methods: Tuple of HTTP methods considered safe. Defaults to
                     ``('GET', 'HEAD', 'OPTIONS')``.

    Example::

        # Allow anyone to read, but only owner can update/delete
        class ArticleDetailView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [IsSubOwnerOrSafeOnly]
            owner_attribute = 'author_id'
            safe_methods = ('GET', 'HEAD', 'OPTIONS')

            def get_object(self):
                return Article.objects.get(pk=self.kwargs['pk'])

            def get(self, request, pk):
                # Anyone can read
                article = self.get_object()
                self.check_object_permissions(request, article)
                return Response({'title': article.title})

            def put(self, request, pk):
                # Only owner can update
                article = self.get_object()
                self.check_object_permissions(request, article)
                # Update logic
                return Response({'status': 'updated'})

        # Using with ViewSet
        class ArticleViewSet(viewsets.ModelViewSet):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [IsSubOwnerOrSafeOnly]
            owner_attribute = 'user_id'
            safe_methods = ('GET', 'HEAD', 'OPTIONS', 'LIST')
            queryset = Article.objects.all()
            serializer_class = ArticleSerializer

    Raises:
        InsufficientPermission: If non-safe method and token subject doesn't match owner.
        ImproperlyConfigured: If ``owner_attribute`` is not defined.
    """

    message = "Permission Denied - Safe methods only or must be owner"

    def has_object_permission(self, request, view, obj):
        """Check if request method is safe or token subject matches owner.

        Args:
            request: Django REST Framework request with ``auth_jwt`` and ``method``.
            view: View instance with ``owner_attribute`` and ``safe_methods``.
            obj: Object being accessed.

        Returns:
            bool: ``True`` if method is safe or user is owner.

        Raises:
            InsufficientPermission: If authorization fails.
        """
        # Get safe methods from view or use default
        safe_methods = getattr(view, "safe_methods", ("GET", "HEAD", "OPTIONS"))

        # Allow safe methods for all authenticated users
        if request.method in safe_methods:
            return True

        # For unsafe methods, check ownership
        try:
            auth_jwt = request.auth_jwt
            token_sub = getattr(auth_jwt, "sub", None)

            if not token_sub:
                raise InsufficientPermission

            # Get the owner attribute name from view
            owner_attr = getattr(view, "owner_attribute", "user")

            if not hasattr(obj, owner_attr):
                raise ImproperlyConfigured(
                    f"Object does not have attribute '{owner_attr}'. "
                    f"Set owner_attribute on the view to the correct field name."
                )

            # Get the owner value from object
            owner_value = getattr(obj, owner_attr, None)

            # Compare token sub with object owner
            if str(token_sub) != str(owner_value):
                raise InsufficientPermission

            return True

        except AttributeError:
            raise InsufficientPermission


class IsSafeOnly(BasePermission):
    """Permission that only allows safe HTTP methods.

    Restricts access to safe HTTP methods only (GET, HEAD, OPTIONS by default).
    Useful for read-only endpoints where authenticated users can view but not modify.

    Attributes:
        safe_methods: Tuple of HTTP methods considered safe. Defaults to
                     ``('GET', 'HEAD', 'OPTIONS')``.

    Example::

        # Read-only access for all authenticated users
        class ArticleListView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [IsSafeOnly]
            safe_methods = ('GET', 'HEAD', 'OPTIONS')

            def get(self, request):
                articles = Article.objects.all()
                return Response({'articles': list(articles.values())})

            def post(self, request):
                # This will be denied by IsSafeOnly permission
                return Response({'status': 'created'})

        # Custom safe methods including LIST
        class CustomReadOnlyView(APIView):
            authentication_classes = [HasValidAccessToken]
            permission_classes = [IsSafeOnly]
            safe_methods = ('GET', 'HEAD', 'OPTIONS', 'LIST')

            def get(self, request):
                return Response({'data': 'read-only'})

    Raises:
        InsufficientPermission: If request method is not in safe_methods.
    """

    message = "Permission Denied - Safe methods only"

    def has_permission(self, request, view):
        """Check if request method is safe.

        Args:
            request: Django REST Framework request with ``method``.
            view: View instance with optional ``safe_methods`` attribute.

        Returns:
            bool: ``True`` if method is safe.

        Raises:
            InsufficientPermission: If method is not safe.
        """
        # Get safe methods from view or use default
        safe_methods = getattr(view, "safe_methods", ("GET", "HEAD", "OPTIONS"))

        if request.method not in safe_methods:
            raise InsufficientPermission

        return True


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
