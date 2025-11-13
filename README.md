# axioms-drf-py ![PyPI](https://img.shields.io/pypi/v/axioms-drf-py) ![Pepy Total Downloads](https://img.shields.io/pepy/dt/axioms-drf-py)
OAuth2/OIDC authentication and authorization for Django REST Framework APIs. Supports authentication and claim-based fine-grained authorization (scopes, roles, permissions) using JWT tokens.

Works with access tokens issued by various authorization servers including [AWS Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html), [Auth0](https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles), [Okta](https://developer.okta.com/docs/api/oauth2/), [Microsoft Entra](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles), etc.

> **Using Flask or FastAPI?** This package is specifically for Django REST Framework. For Flask applications, use [axioms-flask-py](https://github.com/abhishektiwari/axioms-flask-py). For FastAPI applications, use [axioms-fastapi](https://github.com/abhishektiwari/axioms-fastapi).

![GitHub Release](https://img.shields.io/github/v/release/abhishektiwari/axioms-drf-py)
![GitHub Actions Test Workflow Status](https://img.shields.io/github/actions/workflow/status/abhishektiwari/axioms-drf-py/test.yml?label=tests)
![PyPI - Version](https://img.shields.io/pypi/v/axioms-drf-py)
![Python Wheels](https://img.shields.io/pypi/wheel/axioms-drf-py)
![Python Versions](https://img.shields.io/pypi/pyversions/axioms-drf-py?logo=python&logoColor=white)
![GitHub last commit](https://img.shields.io/github/last-commit/abhishektiwari/axioms-drf-py)
![PyPI - Status](https://img.shields.io/pypi/status/axioms-drf-py)
![License](https://img.shields.io/github/license/abhishektiwari/axioms-drf-py)
![PyPI Downloads](https://img.shields.io/pepy/dt/axioms-drf-py?label=PyPI%20Downloads)

## Features

* JWT token validation with automatic public key retrieval from JWKS endpoints
* Algorithm validation to prevent algorithm confusion attacks (only secure asymmetric algorithms allowed)
* Issuer validation (`iss` claim) to prevent token substitution attacks
* Authentication classes for standard DRF integration
* Permission classes for claim-based authorization: scopes, roles, and permissions
* Object-level permission classes for resource ownership verification
* Support for both OR and AND logic in authorization checks
* Middleware for automatic token extraction and validation
* Flexible configuration with support for custom JWKS and issuer URLs
* Simple integration with Django REST Framework Resource Server or API backends
* Support for custom claim and/or namespaced claims names to support different authorization servers

## Prerequisites

* Python 3.8+
* Django 3.2+
* Django REST Framework 3.12+
* An OAuth2/OIDC authorization server (AWS Cognito, Auth0, Okta, Microsoft Entra, etc.) that can issue JWT access tokens

## Installation

Install the package using pip:

```bash
pip install axioms-drf-py
```

## Quick Start

### 1. Add Middleware

Add the middleware to your Django settings:

```python
MIDDLEWARE = [
    'axioms_drf.middleware.AccessTokenMiddleware',
    # ... other middleware
]
```

### 2. Configuration

The SDK supports the following configuration options in your Django settings:

| Setting | Required | Description |
| --- | --- | --- |
| `AXIOMS_AUDIENCE` | Yes | Expected audience claim in the JWT token. |
| `AXIOMS_DOMAIN` | No | Axioms domain name. Used as the base to construct `AXIOMS_ISS_URL` if not explicitly provided. This is the simplest configuration option for standard OAuth2/OIDC providers. |
| `AXIOMS_ISS_URL` | No | Full issuer URL for validating the `iss` claim in JWT tokens (e.g., `https://auth.example.com/oauth2`). If not provided, constructed as `https://{AXIOMS_DOMAIN}`. Used to construct `AXIOMS_JWKS_URL` if that is not explicitly set. Recommended for security to prevent token substitution attacks. |
| `AXIOMS_JWKS_URL` | No | Full URL to JWKS endpoint (e.g., `https://auth.example.com/.well-known/jwks.json`). If not provided, constructed as `{AXIOMS_ISS_URL}/.well-known/jwks.json` |

**Configuration Hierarchy:**

The SDK uses the following construction order:
1. `AXIOMS_DOMAIN` → constructs → `AXIOMS_ISS_URL` (if not explicitly set)
2. `AXIOMS_ISS_URL` → constructs → `AXIOMS_JWKS_URL` (if not explicitly set)

> **Note:** You must provide at least one of: `AXIOMS_DOMAIN`, `AXIOMS_ISS_URL`, or `AXIOMS_JWKS_URL`. For most use cases, setting only `AXIOMS_DOMAIN` is sufficient.

### 3. Configure Settings

#### Option A: Using `.env` file

Create a `.env` file in your project root:

```bash
AXIOMS_AUDIENCE=your-api-audience

# Set Issuer and JWKS URLs directly (optional, but recommended for security)
AXIOMS_ISS_URL = 'https://your-auth.domain.com'
AXIOMS_JWKS_URL = 'https://your-auth.domain.com/.well-known/jwks.json'

# Optionally, you can set the auth domain and let the SDK construct the URLs
# AXIOMS_DOMAIN = 'your-auth.domain.com'
```

Then load in your `settings.py`:

```python
import environ

env = environ.Env()
environ.Env.read_env()

# Required
AXIOMS_AUDIENCE = env('AXIOMS_AUDIENCE')


AXIOMS_ISS_URL = env('AXIOMS_ISS_URL', default=None)
AXIOMS_JWKS_URL = env('AXIOMS_JWKS_URL', default=None)

# AXIOMS_DOMAIN = env('AXIOMS_DOMAIN', default=None)
```

#### Option B: Direct Configuration

Configure directly in your `settings.py`:

```python
# Required settings
AXIOMS_AUDIENCE = 'your-api-audience'

AXIOMS_ISS_URL = 'https://your-auth.domain.com'
AXIOMS_JWKS_URL = 'https://your-auth.domain.com/.well-known/jwks.json'

# AXIOMS_DOMAIN = 'your-auth.domain.com'  # Simplest option - constructs issuer and JWKS URLs
```

### 4. Use Authentication and Permission Classes

Protect your API views using authentication and permission classes:

```python
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
```

## Guard Your Django REST Framework API Views

### Authentication Classes

| Class | Description |
| --- | --- |
| `HasValidAccessToken` | Validates JWT access token from Authorization header. Performs token signature validation, expiry datetime validation, token audience validation, and issuer validation (if configured). |
| `IsAccessTokenAuthenticated` | Alias for `HasValidAccessToken`. |
| `IsAnyPostOrIsAccessTokenAuthenticated` | Allows POST requests without authentication, requires valid token for other methods. |
| `IsAnyGetOrIsAccessTokenAuthenticated` | Allows GET requests without authentication, requires valid token for other methods. |

### Permission Classes

#### Claim-Based Permissions

| Class | Description | View Attributes |
| --- | --- | --- |
| `HasAccessTokenScopes` | Check scopes in `scope` claim of the access token. | `access_token_scopes` or `access_token_any_scopes` (OR logic)<br/>`access_token_all_scopes` (AND logic) |
| `HasAccessTokenRoles` | Check roles in `roles` claim of the access token. | `access_token_roles` or `access_token_any_roles` (OR logic)<br/>`access_token_all_roles` (AND logic) |
| `HasAccessTokenPermissions` | Check permissions in `permissions` claim of the access token. | `access_token_permissions` or `access_token_any_permissions` (OR logic)<br/>`access_token_all_permissions` (AND logic) |

> **Method-Level Authorization:** All claim-based permission classes support method-level authorization using Python's `@property` decorator. This allows you to define different authorization requirements for each HTTP method (GET, POST, PATCH, DELETE) on the same view. See the [Method-Level Permissions](#method-level-permissions) section for implementation details.

#### Object-Level Permissions

| Class | Description | View Attributes |
| --- | --- | --- |
| `IsSubOwner` | Verifies that the token's `sub` claim matches a specified attribute on the object. Use for owner-only resource access. | `owner_attribute` - Name of the object attribute to compare with `sub` claim (default: `'user'`) |
| `IsSubOwnerOrSafeOnly` | Allows safe methods (GET, HEAD, OPTIONS) for all authenticated users, restricts unsafe methods (POST, PUT, PATCH, DELETE) to owners only. | `owner_attribute` - Name of the object attribute to compare with `sub` claim (default: `'user'`)<br/>`safe_methods` - Tuple of safe HTTP methods (default: `('GET', 'HEAD', 'OPTIONS')`) |

### OR vs AND Logic

Permission classes support both **OR logic** (any claim) and **AND logic** (all claims) through different view attributes. You can also combine both for complex authorization requirements.

#### OR Logic (Default) - Requires ANY of the specified claims:

```python
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
```

#### AND Logic - Requires ALL of the specified claims:

```python
class SecureView(APIView):
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenScopes]
    access_token_all_scopes = ['read:data', 'write:data']  # AND logic

    def post(self, request):
        # User needs BOTH 'read:data' AND 'write:data' scopes
        return Response({'status': 'created'})
```

#### Mixed Logic - Combine OR and AND requirements:

```python
class MixedView(APIView):
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenScopes]
    access_token_any_scopes = ['read:data', 'read:all']  # Needs read:data OR read:all
    access_token_all_scopes = ['openid', 'profile']       # AND needs BOTH openid AND profile

    def get(self, request):
        # User needs: (read:data OR read:all) AND (openid AND profile)
        return Response({'data': 'complex authorization'})
```


## Examples

### Scope-Based Authorization

Check if `openid` or `profile` scope is present in the token:

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from axioms_drf.authentication import HasValidAccessToken
from axioms_drf.permissions import HasAccessTokenScopes

class ProfileView(APIView):
    authentication_classes = [HasValidAccessToken]
    permission_classes = [HasAccessTokenScopes]
    access_token_scopes = ['openid', 'profile']  # OR logic

    def get(self, request):
        return Response({'message': 'All good. You are authenticated!'}, status=status.HTTP_200_OK)
```

### Role-Based Authorization

Check if `sample:role` role is present in the token:

```python
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
```

### Method-Level Permissions

Check permissions at the API method level using properties:

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from axioms_drf.authentication import HasValidAccessToken
from axioms_drf.permissions import HasAccessTokenPermissions

class SamplePermissionView(APIView):
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
```

### Public Endpoints

Allow unauthenticated access for specific HTTP methods:

```python
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
```

### Object-Level Permissions

Restrict access to resources based on ownership using the `sub` claim from the JWT token:

```python
from rest_framework import viewsets
from axioms_drf.authentication import HasValidAccessToken
from axioms_drf.permissions import IsSubOwner

class ArticleViewSet(viewsets.ModelViewSet):
    authentication_classes = [HasValidAccessToken]
    permission_classes = [IsSubOwner]
    owner_attribute = 'author_sub'  # Compare token sub with article.author_sub

    def perform_create(self, serializer):
        # Automatically set the author from the token's sub claim
        serializer.save(author_sub=self.request.user)
```

Allow anyone to read, but only the owner can update or delete:

```python
from rest_framework import viewsets
from axioms_drf.authentication import HasValidAccessToken
from axioms_drf.permissions import IsSubOwnerOrSafeOnly

class ArticleViewSet(viewsets.ModelViewSet):
    authentication_classes = [HasValidAccessToken]
    permission_classes = [IsSubOwnerOrSafeOnly]
    owner_attribute = 'author_sub'  # Compare token sub with article.author_sub

    def perform_create(self, serializer):
        serializer.save(author_sub=self.request.user)
```

## Complete Example

For a complete working example, check out the [example/](example/) folder in this repository.