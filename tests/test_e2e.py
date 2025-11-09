"""End-to-end tests for axioms-drf authentication and authorization.

This module creates test API views with authentication and authorization
and verifies that they work correctly with Django REST Framework.
"""

import json
import time
import pytest
import django
from django.conf import settings
from django.test import override_settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.test import APIRequestFactory
from jwcrypto import jwk
from jwcrypto import jwt as jwcrypto_jwt
from axioms_drf.authentication import HasValidAccessToken
from axioms_drf.permissions import (
    HasAccessTokenScopes, HasAccessTokenRoles, HasAccessTokenPermissions
)

# Configure Django settings before importing models
if not settings.configured:
    settings.configure(
        SECRET_KEY='test-key',
        INSTALLED_APPS=['django.contrib.contenttypes', 'rest_framework'],
        AXIOMS_AUDIENCE='test-audience',
        AXIOMS_JWKS_URL='https://test-domain.com/.well-known/jwks.json',
        CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
    )
    django.setup()


def generate_jwt_token(key, claims):
    """Generate a JWT token with specified claims."""
    token = jwcrypto_jwt.JWT(
        header={"alg": "RS256", "kid": key.kid},
        claims=claims
    )
    token.make_signed_token(key)
    return token.serialize()


# Test views
class PublicAPIView(APIView):
    """Public API view without authentication."""

    def get(self, request):
        return Response({'message': 'Public endpoint - no authentication required'}, status=status.HTTP_200_OK)


class PrivateAPIView(APIView):
    """Private API view with authentication and scope requirements."""
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenScopes]
    access_token_scopes = ['openid', 'profile']

    def get(self, request):
        return Response({'message': 'Private endpoint - authenticated'}, status=status.HTTP_200_OK)


class RoleAPIView(APIView):
    """API view with role-based authorization."""
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenRoles]
    access_token_roles = ['admin', 'editor']

    def get(self, request):
        return Response({'message': 'Sample read.'}, status=status.HTTP_200_OK)

    def post(self, request):
        return Response({'message': 'Sample created.'}, status=status.HTTP_200_OK)

    def patch(self, request):
        return Response({'message': 'Sample updated.'}, status=status.HTTP_200_OK)

    def delete(self, request):
        return Response({'message': 'Sample deleted.'}, status=status.HTTP_200_OK)


class PermissionCreateAPIView(APIView):
    """API view for create permission."""
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenPermissions]
    access_token_permissions = ['sample:create']

    def post(self, request):
        return Response({'message': 'Sample created.'}, status=status.HTTP_200_OK)


class PermissionUpdateAPIView(APIView):
    """API view for update permission."""
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenPermissions]
    access_token_permissions = ['sample:update']

    def patch(self, request):
        return Response({'message': 'Sample updated.'}, status=status.HTTP_200_OK)


class PermissionReadAPIView(APIView):
    """API view for read permission."""
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenPermissions]
    access_token_permissions = ['sample:read']

    def get(self, request):
        return Response({'message': 'Sample read.'}, status=status.HTTP_200_OK)


class PermissionDeleteAPIView(APIView):
    """API view for delete permission."""
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenPermissions]
    access_token_permissions = ['sample:delete']

    def delete(self, request):
        return Response({'message': 'Sample deleted.'}, status=status.HTTP_200_OK)


class MethodLevelPermissionAPIView(APIView):
    """API view with method-level permissions using property."""
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenPermissions]

    @property
    def access_token_permissions(self):
        method_permissions = {
            'GET': ['sample:read'],
            'POST': ['sample:create'],
            'PATCH': ['sample:update'],
            'DELETE': ['sample:delete']
        }
        return method_permissions[self.request.method]

    def get(self, request):
        return Response({'message': 'Sample read.'}, status=status.HTTP_200_OK)

    def post(self, request):
        return Response({'message': 'Sample created.'}, status=status.HTTP_201_CREATED)

    def patch(self, request):
        return Response({'message': 'Sample updated.'}, status=status.HTTP_200_OK)

    def delete(self, request):
        return Response({'message': 'Sample deleted.'}, status=status.HTTP_204_NO_CONTENT)


class AllScopesAPIView(APIView):
    """API view requiring multiple scopes (AND logic)."""
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenScopes]
    access_token_all_scopes = ['read:resource', 'write:resource']

    def get(self, request):
        return Response({'message': 'Requires both read and write scopes'}, status=status.HTTP_200_OK)


class AllRolesAPIView(APIView):
    """API view requiring multiple roles (AND logic)."""
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenRoles]
    access_token_all_roles = ['admin', 'superuser']

    def get(self, request):
        return Response({'message': 'Requires both admin and superuser roles'}, status=status.HTTP_200_OK)


class AllPermissionsAPIView(APIView):
    """API view requiring multiple permissions (AND logic)."""
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenPermissions]
    access_token_all_permissions = ['sample:create', 'sample:delete']

    def get(self, request):
        return Response({'message': 'Requires both create and delete permissions'}, status=status.HTTP_200_OK)


class MixedAuthorizationAPIView(APIView):
    """API view requiring scope AND role AND permission."""
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenScopes, HasAccessTokenRoles, HasAccessTokenPermissions]
    access_token_scopes = ['openid']
    access_token_roles = ['editor']
    access_token_permissions = ['sample:read']

    def get(self, request):
        return Response({'message': 'Requires scope AND role AND permission'}, status=status.HTTP_200_OK)


# Fixtures are in conftest.py

class TestPublicEndpoints:
    """Test public endpoints that don't require authentication."""

    def test_public_endpoint_no_auth(self, factory):
        """Test that public endpoint is accessible without authentication."""
        view = PublicAPIView.as_view()
        request = factory.get('/public')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Public endpoint - no authentication required'


class TestAuthentication:
    """Test authentication with valid and invalid tokens."""

    def test_private_endpoint_no_token(self, factory):
        """Test that private endpoint rejects requests without token."""
        view = PrivateAPIView.as_view()
        request = factory.get('/private')
        response = view(request)
        assert response.status_code == 401

    def test_private_endpoint_invalid_bearer(self, factory):
        """Test that private endpoint rejects invalid bearer format."""
        view = PrivateAPIView.as_view()
        request = factory.get('/private', HTTP_AUTHORIZATION='InvalidBearer token')
        response = view(request)
        assert response.status_code == 401

    def test_private_endpoint_with_valid_token(self, factory, test_key):
        """Test that private endpoint accepts valid token with required scopes."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile email',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = PrivateAPIView.as_view()
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Private endpoint - authenticated'

    def test_private_endpoint_expired_token(self, factory, test_key):
        """Test that private endpoint rejects expired tokens."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile email',
            'exp': now - 3600,  # Expired 1 hour ago
            'iat': now - 7200
        })

        token = generate_jwt_token(test_key, claims)
        view = PrivateAPIView.as_view()
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 401

    def test_private_endpoint_wrong_audience(self, factory, test_key):
        """Test that private endpoint rejects token with wrong audience."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['wrong-audience'],
            'scope': 'openid profile email',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = PrivateAPIView.as_view()
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 401


class TestScopeAuthorization:
    """Test scope-based authorization."""

    def test_scope_with_required_scope(self, factory, test_key):
        """Test that endpoint accepts token with required scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile email',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = PrivateAPIView.as_view()
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200

    def test_scope_without_required_scope(self, factory, test_key):
        """Test that endpoint rejects token without required scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'email',  # Missing 'openid' and 'profile'
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = PrivateAPIView.as_view()
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 403


class TestRoleAuthorization:
    """Test role-based authorization."""

    def test_role_with_required_role(self, factory, test_key):
        """Test that endpoint accepts token with required role."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['admin', 'viewer'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = RoleAPIView.as_view()
        request = factory.get('/role', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Sample read.'

    def test_role_without_required_role(self, factory, test_key):
        """Test that endpoint rejects token without required role."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['viewer'],  # Missing 'admin' or 'editor'
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = RoleAPIView.as_view()
        request = factory.get('/role', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 403

    @override_settings(AXIOMS_ROLES_CLAIMS=['roles', 'https://test-domain.com/claims/roles'])
    def test_role_with_namespaced_claims(self, factory, test_key):
        """Test role checking with namespaced claims."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'https://test-domain.com/claims/roles': ['admin'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = RoleAPIView.as_view()
        request = factory.get('/role', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200

    def test_role_with_expired_token(self, factory, test_key):
        """Test that role endpoint rejects expired token even with valid role."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['admin'],  # Has required role but token is expired
            'exp': now - 3600,  # Expired 1 hour ago
            'iat': now - 7200
        })

        token = generate_jwt_token(test_key, claims)
        view = RoleAPIView.as_view()
        request = factory.get('/role', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 401


class TestPermissionAuthorization:
    """Test permission-based authorization."""

    def test_permission_create_with_valid_permission(self, factory, test_key):
        """Test create endpoint with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:create', 'sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = PermissionCreateAPIView.as_view()
        request = factory.post('/permission/create', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Sample created.'

    def test_permission_create_without_permission(self, factory, test_key):
        """Test create endpoint without required permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:read'],  # Missing 'sample:create'
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = PermissionCreateAPIView.as_view()
        request = factory.post('/permission/create', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 403

    def test_permission_update_with_valid_permission(self, factory, test_key):
        """Test update endpoint with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:update'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = PermissionUpdateAPIView.as_view()
        request = factory.patch('/permission/update', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Sample updated.'

    def test_permission_read_with_valid_permission(self, factory, test_key):
        """Test read endpoint with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = PermissionReadAPIView.as_view()
        request = factory.get('/permission/read', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Sample read.'

    def test_permission_delete_with_valid_permission(self, factory, test_key):
        """Test delete endpoint with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:delete'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = PermissionDeleteAPIView.as_view()
        request = factory.delete('/permission/delete', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Sample deleted.'

    @override_settings(AXIOMS_PERMISSIONS_CLAIMS=['permissions', 'https://test-domain.com/claims/permissions'])
    def test_permission_with_namespaced_claims(self, factory, test_key):
        """Test permission checking with namespaced claims."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'https://test-domain.com/claims/permissions': ['sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = PermissionReadAPIView.as_view()
        request = factory.get('/permission/read', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200

    def test_permission_with_expired_token(self, factory, test_key):
        """Test that permission endpoint rejects expired token even with valid permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:read'],  # Has required permission but token is expired
            'exp': now - 3600,  # Expired 1 hour ago
            'iat': now - 7200
        })

        token = generate_jwt_token(test_key, claims)
        view = PermissionReadAPIView.as_view()
        request = factory.get('/permission/read', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 401

    def test_method_level_permission_get(self, factory, test_key):
        """Test GET method with method-level permissions."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = MethodLevelPermissionAPIView.as_view()
        request = factory.get('/method-permission', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Sample read.'

    def test_method_level_permission_post(self, factory, test_key):
        """Test POST method with method-level permissions."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:create'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = MethodLevelPermissionAPIView.as_view()
        request = factory.post('/method-permission', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 201
        assert response.data['message'] == 'Sample created.'

    def test_method_level_permission_patch(self, factory, test_key):
        """Test PATCH method with method-level permissions."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:update'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = MethodLevelPermissionAPIView.as_view()
        request = factory.patch('/method-permission', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Sample updated.'

    def test_method_level_permission_delete(self, factory, test_key):
        """Test DELETE method with method-level permissions."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:delete'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = MethodLevelPermissionAPIView.as_view()
        request = factory.delete('/method-permission', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 204

    def test_method_level_permission_wrong_permission_for_method(self, factory, test_key):
        """Test that GET with create permission fails."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:create'],  # Has create but trying GET which needs read
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = MethodLevelPermissionAPIView.as_view()
        request = factory.get('/method-permission', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 403


class TestMultipleMethodsEndpoint:
    """Test endpoint that handles multiple HTTP methods with role authorization."""

    def test_role_endpoint_get(self, factory, test_key):
        """Test GET method on role-protected endpoint."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['editor'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = RoleAPIView.as_view()
        request = factory.get('/role', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert 'message' in response.data


class TestANDLogicAuthorization:
    """Test AND logic authorization (all claims required)."""

    def test_all_scopes_with_both_scopes(self, factory, test_key):
        """Test all scopes succeeds when token has both required scopes."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'read:resource write:resource other:scope',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = AllScopesAPIView.as_view()
        request = factory.get('/chaining/scopes', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Requires both read and write scopes'

    def test_all_scopes_with_only_one_scope(self, factory, test_key):
        """Test all scopes fails when token has only one of the required scopes."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'read:resource other:scope',  # Missing write:resource
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = AllScopesAPIView.as_view()
        request = factory.get('/chaining/scopes', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 403

    def test_all_scopes_with_no_scopes(self, factory, test_key):
        """Test all scopes fails when token has neither required scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'other:scope',  # Missing both read:resource and write:resource
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = AllScopesAPIView.as_view()
        request = factory.get('/chaining/scopes', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 403

    def test_all_roles_with_both_roles(self, factory, test_key):
        """Test all roles succeeds when token has both required roles."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['admin', 'superuser', 'viewer'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = AllRolesAPIView.as_view()
        request = factory.get('/chaining/roles', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Requires both admin and superuser roles'

    def test_all_roles_with_only_one_role(self, factory, test_key):
        """Test all roles fails when token has only one of the required roles."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'roles': ['admin', 'viewer'],  # Missing superuser
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = AllRolesAPIView.as_view()
        request = factory.get('/chaining/roles', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 403

    def test_all_permissions_with_both_permissions(self, factory, test_key):
        """Test all permissions succeeds when token has both required permissions."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:create', 'sample:delete', 'sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = AllPermissionsAPIView.as_view()
        request = factory.get('/chaining/permissions', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Requires both create and delete permissions'

    def test_all_permissions_with_only_one_permission(self, factory, test_key):
        """Test all permissions fails when token has only one of the required permissions."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'permissions': ['sample:create', 'sample:read'],  # Missing sample:delete
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = AllPermissionsAPIView.as_view()
        request = factory.get('/chaining/permissions', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 403

    def test_mixed_with_all_claims(self, factory, test_key):
        """Test mixed authorization succeeds when token has all required claims."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile email',
            'roles': ['editor', 'viewer'],
            'permissions': ['sample:read', 'sample:write'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = MixedAuthorizationAPIView.as_view()
        request = factory.get('/chaining/mixed', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert response.data['message'] == 'Requires scope AND role AND permission'

    def test_mixed_missing_scope(self, factory, test_key):
        """Test mixed authorization fails when scope is missing."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'profile email',  # Missing openid
            'roles': ['editor'],
            'permissions': ['sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = MixedAuthorizationAPIView.as_view()
        request = factory.get('/chaining/mixed', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 403

    def test_mixed_missing_role(self, factory, test_key):
        """Test mixed authorization fails when role is missing."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'roles': ['viewer'],  # Missing editor
            'permissions': ['sample:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = MixedAuthorizationAPIView.as_view()
        request = factory.get('/chaining/mixed', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 403

    def test_mixed_missing_permission(self, factory, test_key):
        """Test mixed authorization fails when permission is missing."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'scope': 'openid profile',
            'roles': ['editor'],
            'permissions': ['sample:write'],  # Missing sample:read
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = MixedAuthorizationAPIView.as_view()
        request = factory.get('/chaining/mixed', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 403
