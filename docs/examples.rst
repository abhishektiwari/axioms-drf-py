Examples
========

This page provides practical examples of using axioms-drf-py authentication and permission classes to secure your Django REST Framework API views.

Scope-Based Authorization
--------------------------

Check if ``openid`` or ``profile`` scope is present in the token (OR logic):

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenScopes

   class ProfileView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenScopes]
       access_token_scopes = ['openid', 'profile']  # OR logic

       def get(self, request):
           return Response({'message': 'All good. You are authenticated!'})

**Example JWT Token Payload (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "openid profile email",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** because the token contains ``openid`` in the ``scope`` claim.

**Example JWT Token Payload (Failure):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "email",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** with 403 Forbidden because the token does not contain ``openid`` or ``profile`` in the ``scope`` claim.

Role-Based Authorization
-------------------------

Check if ``sample:role`` role is present in the token:

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from rest_framework import status
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenRoles

   class SampleRoleView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenRoles]
       access_token_roles = ['sample:role']

       def get(self, request):
           return Response({'message': 'Sample read.'}, status=status.HTTP_200_OK)

       def post(self, request):
           return Response({'message': 'Sample created.'}, status=status.HTTP_201_CREATED)

       def patch(self, request):
           return Response({'message': 'Sample updated.'}, status=status.HTTP_200_OK)

       def delete(self, request):
           return Response({'message': 'Sample deleted.'}, status=status.HTTP_204_NO_CONTENT)

**Example JWT Token Payload (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "roles": ["sample:role", "viewer"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** because the token contains ``sample:role`` in the ``roles`` claim.

**Example JWT Token Payload with Namespaced Claims (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "https://your-domain.com/claims/roles": ["sample:role", "admin"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will also **succeed** if you configure custom claim names:

.. code-block:: python

   # In settings.py
   AXIOMS_ROLES_CLAIMS = ['roles', 'https://your-domain.com/claims/roles']

**Example JWT Token Payload (Failure):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "roles": ["viewer", "editor"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** with 403 Forbidden because the token does not contain ``sample:role``.

Permission-Based Authorization
-------------------------------

Check permissions at the API method level using multiple views:

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from rest_framework import status
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenPermissions

   class SampleCreateView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenPermissions]
       access_token_permissions = ['sample:create']

       def post(self, request):
           return Response({'message': 'Sample created.'}, status=status.HTTP_201_CREATED)


   class SampleUpdateView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenPermissions]
       access_token_permissions = ['sample:update']

       def patch(self, request):
           return Response({'message': 'Sample updated.'}, status=status.HTTP_200_OK)


   class SampleReadView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenPermissions]
       access_token_permissions = ['sample:read']

       def get(self, request):
           return Response({'message': 'Sample read.'}, status=status.HTTP_200_OK)


   class SampleDeleteView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenPermissions]
       access_token_permissions = ['sample:delete']

       def delete(self, request):
           return Response({'message': 'Sample deleted.'}, status=status.HTTP_204_NO_CONTENT)

**Example JWT Token Payload (Success for sample:read):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "permissions": ["sample:read", "sample:update"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** for the GET endpoint because the token contains ``sample:read`` in the ``permissions`` claim.

**Example JWT Token Payload with Namespaced Claims (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "https://your-domain.com/claims/permissions": ["sample:create", "sample:delete"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** for POST and DELETE endpoints if you configure custom claim names:

.. code-block:: python

   # In settings.py
   AXIOMS_PERMISSIONS_CLAIMS = ['permissions', 'https://your-domain.com/claims/permissions']

**Example JWT Token Payload (Failure):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "permissions": ["other:read"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** with 403 Forbidden because the token does not contain any of the required ``sample:*`` permissions.

AND Logic - Requiring Multiple Claims
--------------------------------------

Require users to have ALL specified scopes using AND logic:

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenScopes

   class SecureDataView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenScopes]
       access_token_all_scopes = ['read:data', 'write:data']  # AND logic

       def post(self, request):
           # User needs BOTH 'read:data' AND 'write:data' scopes
           return Response({'message': 'Data created successfully'})

**Example JWT Token Payload (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "read:data write:data openid",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** because the token contains both required scopes.

**Example JWT Token Payload (Failure):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "read:data",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** with 403 Forbidden because the token only contains ``read:data`` but not ``write:data``.

Mixed OR and AND Logic
----------------------

Combine OR and AND logic for complex authorization requirements:

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenScopes, HasAccessTokenRoles

   class ComplexAuthView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenScopes]
       # User needs: (read:data OR read:all) AND (openid AND profile)
       access_token_any_scopes = ['read:data', 'read:all']  # OR logic
       access_token_all_scopes = ['openid', 'profile']      # AND logic

       def get(self, request):
           return Response({'data': 'complex authorization passed'})

**Example JWT Token Payload (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "read:data openid profile email",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** because the token has:
- At least one of ``read:data`` or ``read:all`` (has ``read:data``)
- Both ``openid`` and ``profile``

**Example JWT Token Payload (Failure - Missing AND requirement):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "read:data openid",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** because while it has ``read:data`` (satisfies OR requirement), it's missing ``profile`` (fails AND requirement).

Multiple Permission Classes
----------------------------

Combine different permission classes for complex authorization:

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenScopes, HasAccessTokenRoles

   class MultiPermissionView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenScopes, HasAccessTokenRoles]
       access_token_scopes = ['openid', 'profile']  # Needs openid OR profile
       access_token_roles = ['admin', 'editor']      # AND needs admin OR editor

       def get(self, request):
           # User needs: (openid OR profile) AND (admin OR editor)
           return Response({'message': 'Multi-permission access granted'})

**Example JWT Token Payload (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "openid email",
     "roles": ["editor", "viewer"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** because the token has both ``openid`` scope and ``editor`` role.

Method-Level Permissions
-------------------------

Use properties to define different permissions for each HTTP method on the same view:

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from rest_framework import status
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenPermissions

   class MethodLevelPermissionView(APIView):
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

**Example JWT Token Payload for GET (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "permissions": ["sample:read"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This GET request will **succeed** because the token contains ``sample:read`` permission.

**Example JWT Token Payload for POST (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "permissions": ["sample:create"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This POST request will **succeed** because the token contains ``sample:create`` permission.

**Example JWT Token Payload (Failure):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "permissions": ["sample:create"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This GET request will **fail** with 403 Forbidden because the token has ``sample:create`` permission but GET requires ``sample:read``.

ViewSet Action-Specific Permissions
------------------------------------

ViewSets provide a powerful way to define different permissions for each action (list, retrieve, create, update, destroy) using the ``@property`` decorator.

Scope-Based ViewSet Permissions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Define different scopes for each ViewSet action:

.. code-block:: python

   from rest_framework import viewsets
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenScopes

   class BookViewSet(viewsets.ModelViewSet):
       """Books API with action-specific scope requirements."""
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenScopes]
       queryset = Book.objects.all()
       serializer_class = BookSerializer

       @property
       def access_token_scopes(self):
           """Return required scopes based on the current action."""
           action_scopes = {
               'list': ['book:read'],           # GET /books/
               'retrieve': ['book:read'],       # GET /books/{id}/
               'create': ['book:create'],       # POST /books/
               'update': ['book:update'],       # PUT /books/{id}/
               'partial_update': ['book:update'], # PATCH /books/{id}/
               'destroy': ['book:delete'],      # DELETE /books/{id}/
           }
           return action_scopes.get(self.action, [])

**Example JWT Token Payload (Success for list/retrieve):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "book:read openid",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** for ``GET /books/`` (list) and ``GET /books/1/`` (retrieve) because the token contains ``book:read`` scope.

**Example JWT Token Payload (Success for create):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "book:create openid",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** for ``POST /books/`` because the token contains ``book:create`` scope.

**Example JWT Token Payload (Failure):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "book:read openid",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** with 403 Forbidden for ``POST /books/`` (create) because the token only has ``book:read`` scope, not ``book:create``.

Role-Based ViewSet Permissions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Define different roles for each ViewSet action:

.. code-block:: python

   from rest_framework import viewsets
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenRoles

   class UserViewSet(viewsets.ModelViewSet):
       """User management with role-based permissions."""
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenRoles]
       queryset = User.objects.all()
       serializer_class = UserSerializer

       @property
       def access_token_roles(self):
           """Return required roles based on the current action."""
           action_roles = {
               'list': ['viewer', 'admin'],      # Viewers can list
               'retrieve': ['viewer', 'admin'],  # Viewers can view details
               'create': ['admin'],              # Only admins can create
               'update': ['admin'],              # Only admins can update
               'partial_update': ['admin'],      # Only admins can patch
               'destroy': ['admin'],             # Only admins can delete
           }
           return action_roles.get(self.action, [])

**Example JWT Token Payload (Success for viewer):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "roles": ["viewer"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** for ``GET /users/`` (list) and ``GET /users/1/`` (retrieve) because the token contains ``viewer`` role.

**Example JWT Token Payload (Failure for viewer trying to create):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "roles": ["viewer"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** with 403 Forbidden for ``POST /users/`` because the ``viewer`` role is not authorized for the ``create`` action (requires ``admin``).

Permission-Based ViewSet Permissions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Define different permissions for each ViewSet action:

.. code-block:: python

   from rest_framework import viewsets
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenPermissions

   class DocumentViewSet(viewsets.ModelViewSet):
       """Document management with fine-grained permissions."""
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenPermissions]
       queryset = Document.objects.all()
       serializer_class = DocumentSerializer

       @property
       def access_token_permissions(self):
           """Return required permissions based on the current action."""
           action_permissions = {
               'list': ['document:list'],
               'retrieve': ['document:read'],
               'create': ['document:create'],
               'update': ['document:update'],
               'partial_update': ['document:update'],
               'destroy': ['document:delete'],
           }
           return action_permissions.get(self.action, [])

**Example JWT Token Payload (Success for read operations):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "permissions": ["document:list", "document:read"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** for ``GET /documents/`` (list) and ``GET /documents/1/`` (retrieve) because the token contains both required permissions.

Custom ViewSet Actions
^^^^^^^^^^^^^^^^^^^^^^^

Define permissions for custom ViewSet actions:

.. code-block:: python

   from rest_framework import viewsets
   from rest_framework.decorators import action
   from rest_framework.response import Response
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenScopes

   class ArticleViewSet(viewsets.ModelViewSet):
       """Article management with custom actions."""
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenScopes]
       queryset = Article.objects.all()
       serializer_class = ArticleSerializer

       @property
       def access_token_scopes(self):
           """Return required scopes based on the current action."""
           action_scopes = {
               'list': ['article:read'],
               'retrieve': ['article:read'],
               'create': ['article:create'],
               'update': ['article:update'],
               'partial_update': ['article:update'],
               'destroy': ['article:delete'],
               'publish': ['article:publish'],     # Custom action
               'archive': ['article:archive'],     # Custom action
           }
           return action_scopes.get(self.action, [])

       @action(detail=True, methods=['post'])
       def publish(self, request, pk=None):
           """Publish an article (requires article:publish scope)."""
           article = self.get_object()
           article.published = True
           article.save()
           return Response({'status': 'published'})

       @action(detail=True, methods=['post'])
       def archive(self, request, pk=None):
           """Archive an article (requires article:archive scope)."""
           article = self.get_object()
           article.archived = True
           article.save()
           return Response({'status': 'archived'})

**Example JWT Token Payload (Success for custom action):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "article:publish openid",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** for ``POST /articles/1/publish/`` because the token contains ``article:publish`` scope.

Dynamic Permissions Based on Request Data
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use request data to dynamically determine required permissions:

.. code-block:: python

   from rest_framework import viewsets
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenScopes

   class ReportViewSet(viewsets.ModelViewSet):
       """Reports with dynamic scope requirements."""
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenScopes]
       queryset = Report.objects.all()
       serializer_class = ReportSerializer

       @property
       def access_token_scopes(self):
           """Return scopes based on action and request data."""
           if self.action == 'create':
               # Check if creating a sensitive report
               report_type = self.request.data.get('type')
               if report_type == 'financial':
                   return ['report:create:financial']
               return ['report:create']

           action_scopes = {
               'list': ['report:read'],
               'retrieve': ['report:read'],
               'update': ['report:update'],
               'destroy': ['report:delete'],
           }
           return action_scopes.get(self.action, [])

**Example JWT Token Payload (Success for standard report):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "report:create openid",
     "exp": 1735689600,
     "iat": 1735686000
   }

This POST request with ``{"type": "standard"}`` will **succeed** because the token contains ``report:create`` scope.

**Example JWT Token Payload (Failure for financial report):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "report:create openid",
     "exp": 1735689600,
     "iat": 1735686000
   }

This POST request with ``{"type": "financial"}`` will **fail** with 403 Forbidden because it requires ``report:create:financial`` scope, not just ``report:create``.

Public Endpoints
-----------------

Allow unauthenticated access for specific HTTP methods:

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from axioms_drf.authentication import IsAnyGetOrIsAccessTokenAuthenticated

   class PublicReadView(APIView):
       authentication_classes = [IsAnyGetOrIsAccessTokenAuthenticated]

       def get(self, request):
           # Anyone can read (no authentication required)
           return Response({'articles': []})

       def post(self, request):
           # Requires valid JWT token to create
           return Response({'status': 'created'})

Object-Level Permissions
-------------------------

Restrict access to resources based on ownership using the ``sub`` claim from the JWT token.

Owner-Only Access
^^^^^^^^^^^^^^^^^^

Use ``IsSubOwner`` to restrict all operations to the resource owner:

.. code-block:: python

   from rest_framework import viewsets
   from rest_framework.response import Response
   from rest_framework import status
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import IsSubOwner

   class ArticleViewSet(viewsets.ModelViewSet):
       """Only the owner (matched by sub claim) can access their articles."""
       authentication_classes = [HasValidAccessToken]
       permission_classes = [IsSubOwner]
       owner_attribute = 'author_sub'  # Compare token sub with article.author_sub
       queryset = Article.objects.all()
       serializer_class = ArticleSerializer

       def perform_create(self, serializer):
           # Automatically set the author from the token's sub claim
           serializer.save(author_sub=self.request.user)

**Example JWT Token Payload (Success for owner):**

.. code-block:: json

   {
     "sub": "user123",
     "iss": "https://your-auth.domain.com",
     "aud": "your-api-audience",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** for operations on articles where ``article.author_sub == "user123"``.

**Example JWT Token Payload (Failure for non-owner):**

.. code-block:: json

   {
     "sub": "user456",
     "iss": "https://your-auth.domain.com",
     "aud": "your-api-audience",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** with 403 Forbidden when attempting to access or modify articles where ``article.author_sub == "user123"`` because the token's ``sub`` claim (``user456``) doesn't match the article's ``author_sub`` (``user123``).

Public Read, Owner-Only Modify
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use ``IsSubOwnerOrSafeOnly`` to allow anyone to read, but only owners can update/delete:

.. code-block:: python

   from rest_framework import viewsets
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import IsSubOwnerOrSafeOnly

   class ArticleViewSet(viewsets.ModelViewSet):
       """Anyone can read articles, only owners can update/delete."""
       authentication_classes = [HasValidAccessToken]
       permission_classes = [IsSubOwnerOrSafeOnly]
       owner_attribute = 'author_sub'
       queryset = Article.objects.all()
       serializer_class = ArticleSerializer

       def perform_create(self, serializer):
           serializer.save(author_sub=self.request.user)

**Example JWT Token Payload (Success for GET - any authenticated user):**

.. code-block:: json

   {
     "sub": "user456",
     "iss": "https://your-auth.domain.com",
     "aud": "your-api-audience",
     "exp": 1735689600,
     "iat": 1735686000
   }

This GET request will **succeed** for any authenticated user, regardless of ownership.

**Example JWT Token Payload (Success for PATCH/DELETE - owner only):**

.. code-block:: json

   {
     "sub": "user123",
     "iss": "https://your-auth.domain.com",
     "aud": "your-api-audience",
     "exp": 1735689600,
     "iat": 1735686000
   }

This PATCH or DELETE request will **succeed** only if the token's ``sub`` claim matches the article's ``author_sub`` field.

**Example JWT Token Payload (Failure for PATCH/DELETE - non-owner):**

.. code-block:: json

   {
     "sub": "user456",
     "iss": "https://your-auth.domain.com",
     "aud": "your-api-audience",
     "exp": 1735689600,
     "iat": 1735686000
   }

This PATCH or DELETE request will **fail** with 403 Forbidden because the token's ``sub`` claim doesn't match the article's owner.

Using with APIView
^^^^^^^^^^^^^^^^^^

Object-level permissions also work with standard APIView (not just ViewSets):

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from rest_framework import status
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import IsSubOwner

   class ArticleDetailView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [IsSubOwner]
       owner_attribute = 'author_id'

       def get_object(self, pk):
           return Article.objects.get(pk=pk)

       def get(self, request, pk):
           article = self.get_object(pk)
           self.check_object_permissions(request, article)
           return Response({'title': article.title})

       def patch(self, request, pk):
           article = self.get_object(pk)
           self.check_object_permissions(request, article)
           # Update article logic here
           return Response({'status': 'updated'})

       def delete(self, request, pk):
           article = self.get_object(pk)
           self.check_object_permissions(request, article)
           article.delete()
           return Response(status=status.HTTP_204_NO_CONTENT)

.. important::
   When using object-level permissions with APIView, you must:

   1. Set the ``owner_attribute`` on the view to specify which field contains the owner identifier
   2. Call ``self.check_object_permissions(request, obj)`` after retrieving the object

   ViewSets automatically call ``check_object_permissions`` for detail actions (retrieve, update, destroy).

Complete Django REST Framework Application
-------------------------------------------

For a complete working example, check out the `example application <https://github.com/abhishektiwari/axioms-drf-py/tree/master/example>`_
in this repository. The sample demonstrates a fully functional Django REST Framework application with authentication and authorization.
