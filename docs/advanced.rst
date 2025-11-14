Advanced Usage
==============

This page covers advanced usage patterns for `axioms-drf-py` authentication and permission classes.

Using Properties for Dynamic Permissions
-----------------------------------------

Properties provide a powerful way to dynamically determine permissions based on the HTTP method, request data, or other conditions.

Method-Level Permissions with Properties
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use the ``@property`` decorator to return different permission requirements based on the request method:

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from rest_framework import status
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenPermissions

   class ArticleView(APIView):
       """Article endpoint with method-level permissions."""
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenPermissions]

       @property
       def access_token_permissions(self):
           """Return different permissions based on HTTP method."""
           method_permissions = {
               'GET': ['article:read'],
               'POST': ['article:create'],
               'PATCH': ['article:update'],
               'PUT': ['article:update'],
               'DELETE': ['article:delete']
           }
           return method_permissions.get(self.request.method, [])

       def get(self, request):
           """Read article - requires article:read permission."""
           return Response({'articles': []})

       def post(self, request):
           """Create article - requires article:create permission."""
           return Response({'id': 1}, status=status.HTTP_201_CREATED)

       def patch(self, request):
           """Update article - requires article:update permission."""
           return Response({'updated': True})

       def delete(self, request):
           """Delete article - requires article:delete permission."""
           return Response(status=status.HTTP_204_NO_CONTENT)

Dynamic Scopes Based on Request Data
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use properties to determine required scopes based on request data:

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from rest_framework import status
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenScopes

   class DocumentView(APIView):
       """Document endpoint with dynamic scope requirements."""
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenScopes]

       @property
       def access_token_scopes(self):
           """Return scopes based on document sensitivity."""
           # For GET requests, check query parameter
           if self.request.method == 'GET':
               sensitivity = self.request.query_params.get('sensitivity', 'normal')
               if sensitivity == 'confidential':
                   return ['read:confidential']
               return ['read:documents']

           # For POST requests, check request body
           elif self.request.method == 'POST':
               sensitivity = self.request.data.get('sensitivity', 'normal')
               if sensitivity == 'confidential':
                   return ['create:confidential']
               return ['create:documents']

           return ['read:documents']

       def get(self, request):
           """Get documents - scope depends on sensitivity."""
           sensitivity = request.query_params.get('sensitivity', 'normal')
           return Response({
               'documents': [],
               'sensitivity': sensitivity
           })

       def post(self, request):
           """Create document - scope depends on sensitivity."""
           return Response({'id': 1}, status=status.HTTP_201_CREATED)

Combining Multiple Permission Types
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use properties to dynamically set multiple permission types (``scopes``, ``roles``, ``permissions``):

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import (
       HasAccessTokenScopes,
       HasAccessTokenRoles,
       HasAccessTokenPermissions
   )

   class AdminView(APIView):
       """Admin endpoint with dynamic multi-type permissions."""
       authentication_classes = [HasValidAccessToken]
       permission_classes = [
           HasAccessTokenScopes,
           HasAccessTokenRoles,
           HasAccessTokenPermissions
       ]

       @property
       def access_token_scopes(self):
           """All methods require openid scope."""
           return ['openid', 'profile']

       @property
       def access_token_roles(self):
           """Return roles based on HTTP method."""
           if self.request.method in ['DELETE', 'PATCH']:
               # Destructive operations require admin role
               return ['admin']
           # Read operations require editor or admin
           return ['editor', 'admin']

       @property
       def access_token_permissions(self):
           """Return permissions based on HTTP method."""
           method_permissions = {
               'GET': ['admin:read'],
               'POST': ['admin:create'],
               'PATCH': ['admin:update'],
               'DELETE': ['admin:delete']
           }
           return method_permissions.get(self.request.method, [])

       def get(self, request):
           """Requires: openid+profile scopes, editor OR admin role, admin:read permission."""
           return Response({'users': []})

       def post(self, request):
           """Requires: openid+profile scopes, editor OR admin role, admin:create permission."""
           return Response({'id': 1}, status=201)

       def patch(self, request, pk):
           """Requires: openid+profile scopes, admin role, admin:update permission."""
           return Response({'updated': True})

       def delete(self, request, pk):
           """Requires: openid+profile scopes, admin role, admin:delete permission."""
           return Response(status=204)

Using Properties with ViewSets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

ViewSets can also use properties for action-specific permissions:

.. code-block:: python

   from rest_framework import viewsets
   from rest_framework.decorators import action
   from rest_framework.response import Response
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenPermissions

   class ArticleViewSet(viewsets.ModelViewSet):
       """ViewSet with action-specific permissions."""
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenPermissions]
       queryset = Article.objects.all()
       serializer_class = ArticleSerializer

       @property
       def access_token_permissions(self):
           """Return permissions based on ViewSet action."""
           action_permissions = {
               'list': ['article:read'],
               'retrieve': ['article:read'],
               'create': ['article:create'],
               'update': ['article:update'],
               'partial_update': ['article:update'],
               'destroy': ['article:delete'],
               'publish': ['article:publish'],  # Custom action
               'archive': ['article:archive'],   # Custom action
           }
           return action_permissions.get(self.action, [])

       @action(detail=True, methods=['post'])
       def publish(self, request, pk=None):
           """Publish article - requires article:publish permission."""
           article = self.get_object()
           article.published = True
           article.save()
           return Response({'status': 'published'})

       @action(detail=True, methods=['post'])
       def archive(self, request, pk=None):
           """Archive article - requires article:archive permission."""
           article = self.get_object()
           article.archived = True
           article.save()
           return Response({'status': 'archived'})

OR and AND Logic with Properties
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use properties to dynamically set both OR and AND logic requirements:

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenScopes, HasAccessTokenRoles

   class ComplexPermissionView(APIView):
       """View with complex permission logic."""
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenScopes, HasAccessTokenRoles]

       @property
       def access_token_any_scopes(self):
           """User needs ANY of these scopes (OR logic)."""
           return ['read:data', 'read:all']

       @property
       def access_token_all_scopes(self):
           """User needs ALL of these scopes (AND logic)."""
           return ['openid', 'profile']

       @property
       def access_token_any_roles(self):
           """User needs ANY of these roles (OR logic)."""
           if self.request.method == 'DELETE':
               return ['admin']  # Only admin can delete
           return ['user', 'editor', 'admin']

       @property
       def access_token_all_roles(self):
           """User needs ALL of these roles (AND logic)."""
           # For sensitive operations, require both verified and active roles
           if self.request.method in ['DELETE', 'PATCH']:
               return ['verified', 'active']
           return []

       def get(self, request):
           """
           Requires:
           - (read:data OR read:all) AND (openid AND profile) scopes
           - (user OR editor OR admin) roles
           """
           return Response({'data': 'success'})

       def delete(self, request):
           """
           Requires:
           - (read:data OR read:all) AND (openid AND profile) scopes
           - admin role AND (verified AND active) roles
           """
           return Response(status=204)

Object-Level Permissions with Properties
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Combine object-level permissions with properties for dynamic owner attribute:

.. code-block:: python

   from rest_framework import viewsets
   from rest_framework.response import Response
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import IsSubOwner

   class DynamicOwnerViewSet(viewsets.ModelViewSet):
       """ViewSet with dynamic owner attribute."""
       authentication_classes = [HasValidAccessToken]
       permission_classes = [IsSubOwner]
       queryset = Article.objects.all()
       serializer_class = ArticleSerializer

       @property
       def owner_attribute(self):
           """
           Dynamically determine which field contains the owner identifier.
           Different models might use different field names.
           """
           model = self.get_queryset().model

           # Check model for common owner field names
           if hasattr(model, 'author_sub'):
               return 'author_sub'
           elif hasattr(model, 'owner_sub'):
               return 'owner_sub'
           elif hasattr(model, 'user_id'):
               return 'user_id'

           # Default fallback
           return 'user'

       def perform_create(self, serializer):
           """Set the owner from token's sub claim."""
           owner_field = self.owner_attribute
           serializer.save(**{owner_field: self.request.user})

Best Practices
--------------

1. **Prefer Class-Based Views with Properties**

   Properties provide better control and are more maintainable than setting attributes on function views.

2. **Use Type Hints**

   .. code-block:: python

      from typing import List

      @property
      def access_token_scopes(self) -> List[str]:
          return ['read:data']

3. **Cache Property Results if Expensive**

   .. code-block:: python

      from functools import cached_property

      @cached_property
      def access_token_permissions(self) -> List[str]:
          # Expensive computation here
          return self._compute_permissions()

4. **Document Permission Requirements**

   Always document what permissions each endpoint requires in docstrings.

5. **Test All Permission Combinations**

   When using complex permission logic with properties, ensure thorough test coverage.

Common Pitfalls
---------------

**Pitfall 1: Setting Attributes on Function Views**

.. code-block:: python

   # DON'T DO THIS - Not thread-safe
   @api_view(['GET'])
   @permission_classes([HasAccessTokenScopes])
   def my_view(request):
       my_view.access_token_scopes = ['read:data']  # Unsafe
       return Response({'data': 'ok'})

.. tip::  Use class-based views with properties instead.

**Pitfall 2: Accessing request.data in Property for GET Requests**

.. code-block:: python

   # DON'T DO THIS
   @property
   def access_token_scopes(self):
       # request.data is for POST/PUT/PATCH, not GET
       if self.request.method == 'GET':
           value = self.request.data.get('key')  # Wrong
       return ['read:data']

.. tip:: Use ``request.query_params`` for GET requests, ``request.data`` for ``POST``/``PUT``/``PATCH``.

**Pitfall 3: Returning Mutable Default**

.. code-block:: python

   # DON'T DO THIS
   @property
   def access_token_scopes(self):
       scopes = ['openid']  # Mutable list
       if some_condition:
           scopes.append('profile')
       return scopes

.. tip:: Create a new list each time or use tuple for immutable defaults.

.. code-block:: python

   # DO THIS
   @property
   def access_token_scopes(self):
       base_scopes = ['openid']
       if some_condition:
           return base_scopes + ['profile']
       return base_scopes

See Also
--------

* :doc:`examples` - Basic usage examples
* :doc:`issuers` - Issuer configuration for different providers
* `Django REST Framework - Views <https://www.django-rest-framework.org/api-guide/views/>`_
* `Django REST Framework - ViewSets <https://www.django-rest-framework.org/api-guide/viewsets/>`_
