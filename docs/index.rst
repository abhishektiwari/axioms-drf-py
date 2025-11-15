Welcome to axioms-drf-py documentation!
==========================================

OAuth2/OIDC authentication and authorization for Django REST Framework APIs. Supports authentication and claim-based fine-grained authorization (scopes, roles, permissions) using JWT tokens.

Works with access tokens issued by various authorization servers including `AWS Cognito <https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html>`_, `Auth0 <https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles>`_, `Okta <https://developer.okta.com/docs/api/oauth2/>`_, `Microsoft Entra <https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles>`_, `Keyclock <https://www.keycloak.org/securing-apps/oidc-layers#_oauth21-support>`_, etc.

.. note::
   **Using Flask or FastAPI?** This package is specifically for Django REST Framework. For Flask applications, use `axioms-flask-py <https://github.com/abhishektiwari/axioms-flask-py>`_. For FastAPI applications, use `axioms-fastapi <https://github.com/abhishektiwari/axioms-fastapi>`_.

.. image:: https://img.shields.io/github/v/release/abhishektiwari/axioms-drf-py
   :alt: GitHub Release
   :target: https://github.com/abhishektiwari/axioms-drf-py/releases

.. image:: https://img.shields.io/github/actions/workflow/status/abhishektiwari/axioms-drf-py/test.yml?label=tests
   :alt: GitHub Actions Test Workflow Status
   :target: https://github.com/abhishektiwari/axioms-drf-py/actions/workflows/test.yml

.. image:: https://img.shields.io/github/license/abhishektiwari/axioms-drf-py
   :alt: License

.. image:: https://img.shields.io/github/last-commit/abhishektiwari/axioms-drf-py
   :alt: GitHub Last Commit

.. image:: https://img.shields.io/pypi/v/axioms-drf-py
   :alt: PyPI Version

.. image:: https://img.shields.io/pypi/status/axioms-drf-py
   :alt: PyPI - Status

.. image:: https://img.shields.io/pepy/dt/axioms-drf-py?label=PyPI%20Downloads
   :alt: PyPI Downloads
   :target: https://pypi.org/project/axioms-drf-py/

.. image:: https://img.shields.io/pypi/pyversions/axioms-drf-py?logo=python&logoColor=white
   :alt: Python Versions

.. image:: https://www.codefactor.io/repository/github/abhishektiwari/axioms-drf-py/badge
   :target: https://www.codefactor.io/repository/github/abhishektiwari/axioms-drf-py
   :alt: CodeFactor

.. image:: https://codecov.io/gh/abhishektiwari/axioms-drf-py/graph/badge.svg?token=FUZV5Q67E1 
   :target: https://codecov.io/gh/abhishektiwari/axioms-drf-py

When to use ``axioms-drf-py``?
----------------------------

Use ``axioms-drf-py`` in your Django REST Framework backend to securely validate JWT access
tokens issued by OAuth2/OIDC authorization servers like `AWS Cognito <https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html>`_,
`Auth0 <https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles>`_,
`Okta <https://developer.okta.com/docs/api/oauth2/>`_, `Microsoft Entra <https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles>`_, `Keyclock <https://www.keycloak.org/securing-apps/oidc-layers#_oauth21-support>`_,
etc. Clients - such as single-page applications (React, Vue), mobile apps, or AI agents—obtain access tokens from the authorization server and send them to your backend. In response, ``axioms-drf-py`` fetches JSON Web Key Set (JWKS) from the issuer, validates token signatures, enforces audience/issuer claims, and provides scope, role, and permission-based authorization for your API endpoints.

.. image:: https://static.abhishek-tiwari.com/axioms/oauth2-oidc-v3.png
   :alt: When to use Axioms package

How it is different?
--------------------
Unlike other DRF plugins, ``axioms-drf-py`` focuses exclusively on protecting resource servers, by letting authorization servers do what they do best. This separation of concerns raises the security bar by:

- Delegates authorization to battle-tested OAuth2/OIDC providers
- Works seamlessly with any OAuth2/OIDC ID with simple configuration
- Enterprise-ready defaults using current JWT and OAuth 2.1 best practices

Features
--------

* JWT token validation with automatic public key retrieval from JWKS endpoints
* Algorithm validation to prevent algorithm confusion attacks (only secure asymmetric algorithms allowed)
* Issuer validation (``iss`` claim) to prevent token substitution attacks
* Authentication classes for standard DRF integration
* Permission classes for claim-based authorization: ``scopes``, ``roles``, and ``permissions``
* Object-level permission classes for resource ownership verification
* Support for both OR and AND logic in authorization checks
* Middleware for automatic token extraction and validation
* Flexible configuration with support for custom JWKS and issuer URLs
* Simple integration with Django REST Framework Resource Server or API backends
* Support for custom claim and/or namespaced claims names to support different authorization servers

Prerequisites
-------------

* Python 3.8+
* Django 3.2+
* Django REST Framework 3.12+
* An OAuth2/OIDC authorization server (AWS Cognito, Auth0, Okta, Microsoft Entra, etc.) that can issue JWT access tokens

Installation
------------

Install the package using pip:

.. code-block:: bash

   pip install axioms-drf-py

Quick Start
-----------

1. Add the middleware to your Django settings:

.. code-block:: python

   MIDDLEWARE = [
       'axioms_drf.middleware.AccessTokenMiddleware',
       # ... other middleware
   ]

2. Configure your Django settings with required variables:

**Option A: Using .env file**

Create a ``.env`` file in your project root:

.. code-block:: bash

   AXIOMS_AUDIENCE=your-api-audience

   # Set Issuer and JWKS URLs directly (optional, but recommended for security)
   AXIOMS_ISS_URL=https://your-auth.domain.com
   AXIOMS_JWKS_URL=https://your-auth.domain.com/.well-known/jwks.json

   # Optionally, you can set the auth domain and let the SDK construct the URLs
   # AXIOMS_DOMAIN=your-auth.domain.com

Then load in your ``settings.py``:

.. code-block:: python

   import environ

   env = environ.Env()
   environ.Env.read_env()

   # Required
   AXIOMS_AUDIENCE = env('AXIOMS_AUDIENCE')

   AXIOMS_ISS_URL = env('AXIOMS_ISS_URL', default=None)
   AXIOMS_JWKS_URL = env('AXIOMS_JWKS_URL', default=None)

   # AXIOMS_DOMAIN = env('AXIOMS_DOMAIN', default=None)

**Option B: Direct Configuration**

Configure directly in your ``settings.py``:

.. code-block:: python

   # Required settings
   AXIOMS_AUDIENCE = 'your-api-audience'

   # Set Issuer and JWKS URLs directly (optional, but recommended for security)
   AXIOMS_ISS_URL = 'https://your-auth.domain.com'
   AXIOMS_JWKS_URL = 'https://your-auth.domain.com/.well-known/jwks.json'

   # Optionally, you can set the auth domain and let the SDK construct the URLs
   # AXIOMS_DOMAIN = 'your-auth.domain.com'

3. Use authentication and permission classes in your views:

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenScopes

   class ProtectedView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenScopes]
       access_token_scopes = ['read:data']

       def get(self, request):
           return Response({'message': 'This is protected'})

   class AdminView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenRoles]
       access_token_roles = ['admin']

       def get(self, request):
           return Response({'message': 'Admin access'})

Configuration
-------------

The SDK supports the following configuration options in Django settings:

* ``AXIOMS_AUDIENCE`` (required): Your resource identifier or API audience
* ``AXIOMS_DOMAIN`` (optional): Your auth domain - constructs issuer and JWKS URLs
* ``AXIOMS_ISS_URL`` (optional): Full issuer URL for validating the ``iss`` claim (recommended for security)
* ``AXIOMS_JWKS_URL`` (optional): Full URL to your JWKS endpoint

**Configuration Hierarchy:**

1. ``AXIOMS_DOMAIN`` → constructs → ``AXIOMS_ISS_URL`` (if not explicitly set)
2. ``AXIOMS_ISS_URL`` → constructs → ``AXIOMS_JWKS_URL`` (if not explicitly set)

.. important::
   You must provide at least one of: ``AXIOMS_DOMAIN``, ``AXIOMS_ISS_URL``, or ``AXIOMS_JWKS_URL``.

   For most use cases, setting only ``AXIOMS_DOMAIN`` is sufficient. The SDK will automatically construct the issuer URL and JWKS endpoint URL.

Guard Your DRF Views
--------------------

Use the following authentication and permission classes to protect your API views:

Authentication Classes
^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 30 50 20

   * - Authentication Class
     - Description
     - Parameters
   * - ``HasValidAccessToken``
     - Validates JWT access token from Authorization header. Performs token signature validation, expiry datetime validation, token audience validation, and issuer validation (if configured). Should be set as the authentication class on protected views.
     - None
   * - ``IsAccessTokenAuthenticated``
     - Alias for ``HasValidAccessToken``.
     - None
   * - ``IsAnyPostOrIsAccessTokenAuthenticated``
     - Allows POST requests without authentication, requires valid token for other methods.
     - None
   * - ``IsAnyGetOrIsAccessTokenAuthenticated``
     - Allows GET requests without authentication, requires valid token for other methods.
     - None

Permission Classes
^^^^^^^^^^^^^^^^^^

Claim-Based Permissions
"""""""""""""""""""""""

.. list-table::
   :header-rows: 1
   :widths: 30 50 20

   * - Permission Class
     - Description
     - View Attributes
   * - ``HasAccessTokenScopes``
     - Check scopes in ``scope`` claim of the access token. Should be used with authentication class.
     - ``access_token_scopes`` or ``access_token_any_scopes`` (OR logic), ``access_token_all_scopes`` (AND logic)
   * - ``HasAccessTokenRoles``
     - Check roles in ``roles`` claim of the access token. Should be used with authentication class.
     - ``access_token_roles`` or ``access_token_any_roles`` (OR logic), ``access_token_all_roles`` (AND logic)
   * - ``HasAccessTokenPermissions``
     - Check permissions in ``permissions`` claim of the access token. Should be used with authentication class.
     - ``access_token_permissions`` or ``access_token_any_permissions`` (OR logic), ``access_token_all_permissions`` (AND logic)

.. note::
   **Method-Level Authorization:** All claim-based permission classes support method-level and ViewSet action-Specific authorization
   using Python's ``@property`` decorator. This allows you to define different authorization requirements for each HTTP method (GET, POST, PATCH, DELETE) 
   on the View or different permissions for each action (list, retrieve, create, update, destroy) of ViewSet. See the examples section for implementation details.

Object-Level Permissions
""""""""""""""""""""""""

.. list-table::
   :header-rows: 1
   :widths: 30 50 20

   * - Permission Class
     - Description
     - View Attributes
   * - ``IsSubOwner``
     - Verifies that the token's ``sub`` claim matches a specified attribute on the object. Use for owner-only resource access.
     - ``owner_attribute`` - Name of the object attribute to compare with ``sub`` claim (default: ``'user'``)
   * - ``IsSubOwnerOrSafeOnly``
     - Allows safe methods (GET, HEAD, OPTIONS) for all authenticated users, restricts unsafe methods (POST, PUT, PATCH, DELETE) to owners only.
     - ``owner_attribute`` - Name of the object attribute (default: ``'user'``), ``safe_methods`` - Tuple of safe HTTP methods (default: ``('GET', 'HEAD', 'OPTIONS')``)

OR vs AND Logic
^^^^^^^^^^^^^^^

Permission classes support both **OR logic** (any claim) and **AND logic** (all claims) through different view attributes. You can also combine both for complex authorization requirements.

**OR Logic (Default)** - Requires ANY of the specified claims:

.. code-block:: python

   from rest_framework.views import APIView
   from rest_framework.response import Response
   from axioms_drf.authentication import HasValidAccessToken
   from axioms_drf.permissions import HasAccessTokenScopes

   class DataView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenScopes]
       access_token_scopes = ['read:data', 'write:data']  # OR logic

       def get(self, request):
           # User needs EITHER 'read:data' OR 'write:data' scope
           return Response({'data': 'success'})

   class AdminView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenRoles]
       access_token_roles = ['admin', 'superuser']  # OR logic

       def get(self, request):
           # User needs EITHER 'admin' OR 'superuser' role
           return Response({'users': []})

**AND Logic** - Requires ALL of the specified claims:

.. code-block:: python

   class SecureView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenScopes]
       access_token_all_scopes = ['read:data', 'write:data']  # AND logic

       def post(self, request):
           # User needs BOTH 'read:data' AND 'write:data' scopes
           return Response({'status': 'created'})

   class SuperAdminView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenRoles]
       access_token_all_roles = ['admin', 'superuser']  # AND logic

       def get(self, request):
           # User needs BOTH 'admin' AND 'superuser' roles
           return Response({'message': 'super admin access'})

**Mixed Logic** - Combine OR and AND requirements:

.. code-block:: python

   class MixedView(APIView):
       authentication_classes = [HasValidAccessToken]
       permission_classes = [HasAccessTokenScopes]
       access_token_any_scopes = ['read:data', 'read:all']  # Needs read:data OR read:all
       access_token_all_scopes = ['openid', 'profile']       # AND needs BOTH openid AND profile

       def get(self, request):
           # User needs: (read:data OR read:all) AND (openid AND profile)
           return Response({'data': 'complex authorization'})

Complete Examples
-----------------

For complete working examples including ViewSet-specific permissions, method-level authorization, and object-level permissions, check out:

* The :doc:`examples` section in this documentation for comprehensive code examples
* The `example <https://github.com/abhishektiwari/axioms-drf-py/tree/main/example>`_ folder in the repository for a working Django project

Contents
--------

.. toctree::
   :maxdepth: 1

   api
   examples
   advanced
   issuers

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
