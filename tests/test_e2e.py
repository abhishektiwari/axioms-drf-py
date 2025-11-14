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
from axioms_drf.authentication import HasValidAccessToken
from axioms_drf.permissions import (
    HasAccessTokenScopes, HasAccessTokenRoles, HasAccessTokenPermissions
)
from rest_framework import viewsets, serializers
from django.db import models
from tests.conftest import generate_jwt_token

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


class AuthOnlyAPIView(APIView):
    """API view with only authentication, no authorization/permissions."""
    authentication_classes = [HasValidAccessToken]

    def get(self, request):
        return Response({'message': 'Authentication-only endpoint'}, status=status.HTTP_200_OK)


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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
            'scope': 'openid profile email',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = PrivateAPIView.as_view()
        request = factory.get('/private', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 401

    @override_settings(AXIOMS_SAFE_METHODS=('HEAD', 'OPTIONS', 'GET'))
    def test_custom_safe_methods(self, factory):
        """Test that custom AXIOMS_SAFE_METHODS configuration works."""
        view = AuthOnlyAPIView.as_view()
        # GET should be allowed without authentication when configured as safe method
        request = factory.get('/auth-only')
        response = view(request)
        # Should succeed because GET is in AXIOMS_SAFE_METHODS
        assert response.status_code == 200
        assert response.data['message'] == 'Authentication-only endpoint'

    def test_options_method_allowed(self, factory):
        """Test that OPTIONS method is allowed without authentication (default)."""
        view = AuthOnlyAPIView.as_view()
        request = factory.options('/auth-only')
        response = view(request)
        # Should succeed because OPTIONS is in default AXIOMS_SAFE_METHODS
        assert response.status_code == 200

    def test_head_method_allowed(self, factory):
        """Test that HEAD method is allowed without authentication (default)."""
        view = AuthOnlyAPIView.as_view()
        request = factory.head('/auth-only')
        response = view(request)
        # Should succeed because HEAD is in default AXIOMS_SAFE_METHODS
        assert response.status_code == 200


class TestScopeAuthorization:
    """Test scope-based authorization."""

    def test_scope_with_required_scope(self, factory, test_key):
        """Test that endpoint accepts token with required scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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
            'iss': 'https://test-domain.com',
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

# Mock model for ViewSet testing
class MockBook:
    """Mock book model for testing ViewSets."""
    def __init__(self, pk, title):
        self.pk = pk
        self.title = title


class BookSerializer(serializers.Serializer):
    """Serializer for MockBook."""
    pk = serializers.IntegerField()
    title = serializers.CharField()


class BookViewSet(viewsets.ViewSet):
    """ViewSet with action-specific scope permissions."""
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenScopes]

    @property
    def access_token_scopes(self):
        """Return different scopes based on ViewSet action."""
        action_scopes = {
            'list': ['book:read'],
            'retrieve': ['book:read'],
            'create': ['book:create'],
            'update': ['book:update'],
            'partial_update': ['book:update'],
            'destroy': ['book:delete'],
        }
        return action_scopes.get(self.action, [])

    def list(self, request):
        """List books - requires book:read scope."""
        books = [MockBook(1, 'Book 1'), MockBook(2, 'Book 2')]
        serializer = BookSerializer(books, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        """Retrieve book - requires book:read scope."""
        book = MockBook(pk, f'Book {pk}')
        serializer = BookSerializer(book)
        return Response(serializer.data)

    def create(self, request):
        """Create book - requires book:create scope."""
        return Response({'id': 1, 'title': 'New Book'}, status=status.HTTP_201_CREATED)

    def update(self, request, pk=None):
        """Update book - requires book:update scope."""
        return Response({'id': pk, 'title': 'Updated Book'})

    def partial_update(self, request, pk=None):
        """Partial update book - requires book:update scope."""
        return Response({'id': pk, 'title': 'Partially Updated Book'})

    def destroy(self, request, pk=None):
        """Delete book - requires book:delete scope."""
        return Response(status=status.HTTP_204_NO_CONTENT)


class DocumentViewSet(viewsets.ViewSet):
    """ViewSet with action-specific permission permissions."""
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenPermissions]

    @property
    def access_token_permissions(self):
        """Return different permissions based on ViewSet action."""
        action_permissions = {
            'list': ['document:read'],
            'retrieve': ['document:read'],
            'create': ['document:create'],
            'update': ['document:update'],
            'partial_update': ['document:update'],
            'destroy': ['document:delete'],
        }
        return action_permissions.get(self.action, [])

    def list(self, request):
        """List documents - requires document:read permission."""
        return Response({'documents': []})

    def retrieve(self, request, pk=None):
        """Retrieve document - requires document:read permission."""
        return Response({'id': pk, 'title': 'Document'})

    def create(self, request):
        """Create document - requires document:create permission."""
        return Response({'id': 1}, status=status.HTTP_201_CREATED)

    def update(self, request, pk=None):
        """Update document - requires document:update permission."""
        return Response({'id': pk, 'updated': True})

    def partial_update(self, request, pk=None):
        """Partial update document - requires document:update permission."""
        return Response({'id': pk, 'updated': True})

    def destroy(self, request, pk=None):
        """Delete document - requires document:delete permission."""
        return Response(status=status.HTTP_204_NO_CONTENT)


@pytest.mark.django_db
class TestViewSetActionPermissions:
    """Test ViewSet with action-specific scope permissions."""

    def test_viewset_list_with_read_scope(self, factory, test_key):
        """Test list action succeeds with read scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scope': 'book:read',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = BookViewSet.as_view({'get': 'list'})
        request = factory.get('/books/', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200
        assert len(response.data) == 2

    def test_viewset_list_without_read_scope(self, factory, test_key):
        """Test list action fails without read scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scope': 'book:create',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = BookViewSet.as_view({'get': 'list'})
        request = factory.get('/books/', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 403

    def test_viewset_retrieve_with_read_scope(self, factory, test_key):
        """Test retrieve action succeeds with read scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scope': 'book:read',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = BookViewSet.as_view({'get': 'retrieve'})
        request = factory.get('/books/1/', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request, pk=1)
        assert response.status_code == 200
        assert response.data['pk'] == 1

    def test_viewset_create_with_create_scope(self, factory, test_key):
        """Test create action succeeds with create scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scope': 'book:create',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = BookViewSet.as_view({'post': 'create'})
        request = factory.post('/books/', {'title': 'New Book'}, HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 201

    def test_viewset_create_without_create_scope(self, factory, test_key):
        """Test create action fails without create scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scope': 'book:read',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = BookViewSet.as_view({'post': 'create'})
        request = factory.post('/books/', {'title': 'New Book'}, HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 403

    def test_viewset_update_with_update_scope(self, factory, test_key):
        """Test update action succeeds with update scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scope': 'book:update',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = BookViewSet.as_view({'put': 'update'})
        request = factory.put('/books/1/', {'title': 'Updated'}, HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request, pk=1)
        assert response.status_code == 200

    def test_viewset_partial_update_with_update_scope(self, factory, test_key):
        """Test partial_update action succeeds with update scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scope': 'book:update',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = BookViewSet.as_view({'patch': 'partial_update'})
        request = factory.patch('/books/1/', {'title': 'Patched'}, HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request, pk=1)
        assert response.status_code == 200

    def test_viewset_destroy_with_delete_scope(self, factory, test_key):
        """Test destroy action succeeds with delete scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scope': 'book:delete',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = BookViewSet.as_view({'delete': 'destroy'})
        request = factory.delete('/books/1/', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request, pk=1)
        assert response.status_code == 204

    def test_viewset_destroy_without_delete_scope(self, factory, test_key):
        """Test destroy action fails without delete scope."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'scope': 'book:read',
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = BookViewSet.as_view({'delete': 'destroy'})
        request = factory.delete('/books/1/', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request, pk=1)
        assert response.status_code == 403


@pytest.mark.django_db
class TestViewSetActionPermissionsWithPermissionClaims:
    """Test ViewSet with action-specific permission claims."""

    def test_viewset_list_with_read_permission(self, factory, test_key):
        """Test list action succeeds with read permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'permissions': ['document:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = DocumentViewSet.as_view({'get': 'list'})
        request = factory.get('/documents/', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 200

    def test_viewset_create_with_create_permission(self, factory, test_key):
        """Test create action succeeds with create permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'permissions': ['document:create'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = DocumentViewSet.as_view({'post': 'create'})
        request = factory.post('/documents/', {'title': 'New Doc'}, HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 201

    def test_viewset_update_with_update_permission(self, factory, test_key):
        """Test update action succeeds with update permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'permissions': ['document:update'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = DocumentViewSet.as_view({'put': 'update'})
        request = factory.put('/documents/1/', {'title': 'Updated'}, HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request, pk=1)
        assert response.status_code == 200

    def test_viewset_destroy_with_delete_permission(self, factory, test_key):
        """Test destroy action succeeds with delete permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'permissions': ['document:delete'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = DocumentViewSet.as_view({'delete': 'destroy'})
        request = factory.delete('/documents/1/', HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request, pk=1)
        assert response.status_code == 204

    def test_viewset_create_without_create_permission(self, factory, test_key):
        """Test create action fails without create permission."""
        now = int(time.time())
        claims = json.dumps({
            'sub': 'user123',
            'aud': ['test-audience'],
            'iss': 'https://test-domain.com',
            'permissions': ['document:read'],
            'exp': now + 3600,
            'iat': now
        })

        token = generate_jwt_token(test_key, claims)
        view = DocumentViewSet.as_view({'post': 'create'})
        request = factory.post('/documents/', {'title': 'New Doc'}, HTTP_AUTHORIZATION=f'Bearer {token}')
        response = view(request)
        assert response.status_code == 403
