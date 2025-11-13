"""Axioms DRF SDK for OAuth2/OIDC authentication and authorization.

OAuth2/OIDC authentication and authorization for Django REST Framework APIs.
Supports authentication and claim-based fine-grained authorization (scopes, roles, permissions)
using JWT tokens.
"""

# Try to get version from setuptools_scm generated file
try:
    from axioms_drf._version import version as __version__
except ImportError:
    # Version file doesn't exist yet (development mode without build)
    __version__ = "0.0.0.dev0"

from .authentication import HasValidAccessToken
from .permissions import (
    HasAccessTokenPermissions,
    HasAccessTokenRoles,
    HasAccessTokenScopes,
    InsufficientPermission,
    IsSafeOnly,
    IsSubOwner,
    IsSubOwnerOrSafeOnly,
)

__all__ = [
    "__version__",
    "HasValidAccessToken",
    "HasAccessTokenScopes",
    "HasAccessTokenRoles",
    "HasAccessTokenPermissions",
    "IsSubOwner",
    "IsSubOwnerOrSafeOnly",
    "IsSafeOnly",
    "InsufficientPermission",
]
