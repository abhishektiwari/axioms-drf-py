# axioms-drf-py ![PyPI](https://img.shields.io/pypi/v/axioms-drf-py)
[Axioms](https://axioms.io) Python client for Django Rest Framework (DRF). Secure your DRF APIs using Axioms Authentication and Authorization.

## Prerequisite

* Python 3.7+
* An [Axioms](https://axioms.io) client which can obtain access token after user's authentication and authorization and include in `Authorization` header of all API request sent to Python/Flask application server.

## Install SDK
Install `axioms-drf-py` in you DRF API project,

```
pip install axioms-drf-py
```

## Basic usage

### Add `.env` file
Create a `.env` file in your main Django app and add following configs,

```
AXIOMS_DOMAIN=<your-axioms-slug>.axioms.io
AXIOMS_AUDIENCE=<your-axioms-resource-identifier>
URL_LIB_SSL_IGNORE=True
```

### Load Config
In your Django project `settings.py`,

```
import os
import environ

env = environ.Env(
    # set casting, default value
    DEBUG=(bool, False)
)
# reading .env file
environ.Env.read_env()

AXIOMS_DOMAIN=env('AXIOMS_DOMAIN')
AXIOMS_AUDIENCE=env('AXIOMS_AUDIENCE')
URL_LIB_SSL_IGNORE=env('URL_LIB_SSL_IGNORE')
```

## Guard API Views
Use authentication and permission classes to guard you API views.

```
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from axioms_drf.authentication import  AccessTokenAuthentication
from axioms_drf.permissions import AccessScopePermission

class Private(APIView):
    authentication_classes = [AccessTokenAuthentication]
    permission_classes = (AccessScopePermission,)
    access_token_scopes = ['openid', 'profile']  # noqa

    def get(self, request, format=None):
        return Response({'message': 'All good. You are authenticated!'}, status=status.HTTP_200_OK)
```

### Authentication classes

#### `AccessTokenAuthentication`
* `AccessTokenAuthentication` checks if access token passed in Authorization header in API call is valid or not. It check signature, time, and audience validity using public for your tenant. 
* Once access token is verified user is authenticated and claims in tokens can be used to perform permission, role, scope checks.

### Permission classes

#### `AccessScopePermission`
* `AccessScopePermission` requires additional attribute `access_token_scopes` on view class.
* `access_token_scopes` accepts an array of strings as `conditional OR` where each string represent a scope (role or permission).
* If any scope provided in `access_token_scopes` is matched with one in access token, SDK will allow access (hence why scopes are `conditional OR`)

For more details please check our [sample-python-drf](https://github.com/axioms-io/sample-python-drf)
