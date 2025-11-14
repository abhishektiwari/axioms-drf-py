"""API views demonstrating different authentication and authorization patterns."""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, viewsets
from axioms_drf.authentication import HasValidAccessToken
from axioms_drf.permissions import (
    HasAccessTokenScopes,
    HasAccessTokenRoles,
    HasAccessTokenPermissions,
    IsSubOwner,
)
from .models import Article, Book
from .serializers import ArticleSerializer, BookSerializer


class PublicView(APIView):
    """Public endpoint - no authentication required."""

    def get(self, request):
        return Response({
            'message': 'This is a public endpoint. No authentication required.',
            'endpoint': '/api/public'
        })


class AuthenticatedView(APIView):
    """Authenticated endpoint - requires valid JWT token."""

    authentication_classes = [HasValidAccessToken]

    def get(self, request):
        return Response({
            'message': 'You are authenticated!',
            'user': request.user,
            'endpoint': '/api/authenticated'
        })


class ScopeProtectedView(APIView):
    """Endpoint protected by scope - requires 'read:messages' scope."""

    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenScopes]
    access_token_scopes = ['read:messages']

    def get(self, request):
        return Response({
            'message': 'You have the required scope!',
            'required_scope': 'read:messages',
            'endpoint': '/api/scope-protected'
        })


class MultipleScopesView(APIView):
    """Endpoint requiring multiple scopes (OR logic) - any one is sufficient."""

    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenScopes]
    access_token_scopes = ['read:messages', 'read:data']

    def get(self, request):
        return Response({
            'message': 'You have at least one of the required scopes!',
            'required_scopes': ['read:messages', 'read:data'],
            'logic': 'OR - any one scope is sufficient',
            'endpoint': '/api/multiple-scopes'
        })


class AllScopesView(APIView):
    """Endpoint requiring all scopes (AND logic) - all must be present."""

    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenScopes]
    access_token_all_scopes = ['read:messages', 'write:messages']

    def get(self, request):
        return Response({
            'message': 'You have all required scopes!',
            'required_scopes': ['read:messages', 'write:messages'],
            'logic': 'AND - all scopes required',
            'endpoint': '/api/all-scopes'
        })


class RoleProtectedView(APIView):
    """Endpoint protected by role - requires 'admin' or 'editor' role."""

    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenRoles]
    access_token_roles = ['admin', 'editor']

    def get(self, request):
        return Response({
            'message': 'You have the required role!',
            'required_roles': ['admin', 'editor'],
            'logic': 'OR - any one role is sufficient',
            'endpoint': '/api/role-protected'
        })


class AllRolesView(APIView):
    """Endpoint requiring all roles (AND logic)."""

    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenRoles]
    access_token_all_roles = ['admin', 'superuser']

    def get(self, request):
        return Response({
            'message': 'You have all required roles!',
            'required_roles': ['admin', 'superuser'],
            'logic': 'AND - all roles required',
            'endpoint': '/api/all-roles'
        })


class PermissionProtectedView(APIView):
    """Endpoint protected by permission - requires 'create:articles' permission."""

    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenPermissions]
    access_token_permissions = ['create:articles']

    def post(self, request):
        return Response({
            'message': 'You have the required permission!',
            'required_permission': 'create:articles',
            'endpoint': '/api/permission-protected'
        }, status=status.HTTP_201_CREATED)


class MultiplePermissionsView(APIView):
    """Endpoint with method-level permissions."""

    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenPermissions]

    @property
    def access_token_permissions(self):
        """Return different permissions based on HTTP method."""
        method_permissions = {
            'GET': ['read:articles'],
            'POST': ['create:articles'],
            'PATCH': ['update:articles'],
            'DELETE': ['delete:articles']
        }
        return method_permissions.get(self.request.method, [])

    def get(self, request):
        return Response({
            'message': 'Reading articles',
            'required_permission': 'read:articles',
            'endpoint': '/api/multiple-permissions'
        })

    def post(self, request):
        return Response({
            'message': 'Article created',
            'required_permission': 'create:articles',
            'endpoint': '/api/multiple-permissions'
        }, status=status.HTTP_201_CREATED)

    def patch(self, request):
        return Response({
            'message': 'Article updated',
            'required_permission': 'update:articles',
            'endpoint': '/api/multiple-permissions'
        })

    def delete(self, request):
        return Response({
            'message': 'Article deleted',
            'required_permission': 'delete:articles',
            'endpoint': '/api/multiple-permissions'
        }, status=status.HTTP_204_NO_CONTENT)


class MixedAuthorizationView(APIView):
    """Endpoint requiring scope AND role AND permission."""

    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenScopes, HasAccessTokenRoles, HasAccessTokenPermissions]
    access_token_scopes = ['openid']
    access_token_roles = ['admin']
    access_token_permissions = ['manage:system']

    def get(self, request):
        return Response({
            'message': 'You have all required authorizations!',
            'required_scope': 'openid',
            'required_role': 'admin',
            'required_permission': 'manage:system',
            'endpoint': '/api/mixed-authorization'
        })


class ArticleViewSet(viewsets.ModelViewSet):
    """ViewSet for Article model with object-level permissions."""

    queryset = Article.objects.all()
    serializer_class = ArticleSerializer
    authentication_classes = [HasValidAccessToken]
    permission_classes = [IsSubOwner]
    owner_attribute = 'author_sub'  # Specify which field contains the owner identifier

    def perform_create(self, serializer):
        """Set the author_sub from the authenticated user's sub claim."""
        serializer.save(author_sub=self.request.user)

    def list(self, request):
        """List all articles (public read)."""
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'message': 'Listing all articles',
            'articles': serializer.data,
            'note': 'Anyone can list articles. Only owners can update/delete their own articles.'
        })

class BookViewSet(viewsets.ModelViewSet):
    """ViewSet for Book model with action-specific scope permissions.
    
    Demonstrates how to use properties to assign different scopes to different
    ViewSet actions (list, retrieve, create, update, destroy).
    """

    queryset = Book.objects.all()
    serializer_class = BookSerializer
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenScopes]

    @property
    def access_token_scopes(self):
        """Return different scopes based on ViewSet action.
        
        - list: book:read
        - retrieve: book:read
        - create: book:create
        - update/partial_update: book:update
        - destroy: book:delete
        """
        action_scopes = {
            'list': ['book:read'],
            'retrieve': ['book:read'],
            'create': ['book:create'],
            'update': ['book:update'],
            'partial_update': ['book:update'],
            'destroy': ['book:delete'],
        }
        return action_scopes.get(self.action, [])
