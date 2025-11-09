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

Complete Django REST Framework Application
-------------------------------------------

For a complete working example, check out the `Django REST Framework sample application <https://github.com/axioms-io/sample-python-django-rest-framework>`_
on GitHub. The sample demonstrates a fully functional Django REST Framework application with authentication and authorization.
