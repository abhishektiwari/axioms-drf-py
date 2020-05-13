import logging
import re
from django.core.exceptions import ImproperlyConfigured
from rest_framework.permissions import BasePermission
from rest_framework.exceptions import APIException
from django.conf import settings
from rest_framework import status

from .helper import check_scopes, check_roles, check_permissions


class HasAccessTokenScopes(BasePermission):
    message = "Permission Denied"

    def has_permission(self, request, view):
        try:
            auth_jwt = request.auth_jwt
            access_token_scopes = self.get_scopes(request, view)
            if hasattr(auth_jwt, "scope") and access_token_scopes:
                if check_scopes(auth_jwt.scope, access_token_scopes):
                    return True
                else:
                    raise InsufficientPermission
            else:
                return False
        except AttributeError:
            raise InsufficientPermission

    def get_scopes(self, request, view):
        try:
            return getattr(view, "access_token_scopes")
        except AttributeError:
            raise ImproperlyConfigured(
                "Define the access_token_scopes attribute for each method"
            )


class HasAccessTokenRoles(BasePermission):
    message = "Permission Denied"

    def has_permission(self, request, view):
        try:
            auth_jwt = request.auth_jwt
            access_token_roles = self.get_roles(request, view)
            token_roles = []
            token_roles = getattr(
                auth_jwt, "https://{}/claims/roles".format(settings.AXIOMS_DOMAIN), [],
            )
            if access_token_roles:
                if check_roles(token_roles, access_token_roles):
                    return True
                else:
                    raise InsufficientPermission
            else:
                return False
        except AttributeError:
            raise InsufficientPermission

    def get_roles(self, request, view):
        try:
            return getattr(view, "access_token_roles")
        except AttributeError:
            raise ImproperlyConfigured(
                "Define the access_token_roles attribute for each method"
            )


class HasAccessTokenPermissions(BasePermission):
    message = "Permission Denied"

    def has_permission(self, request, view):
        try:
            auth_jwt = request.auth_jwt
            access_token_permissions = self.get_permissions(request, view)
            token_permissions = []
            token_permissions = getattr(
                auth_jwt,
                "https://{}/claims/permissions".format(settings.AXIOMS_DOMAIN),
                [],
            )
            if access_token_permissions:
                if check_permissions(token_permissions, access_token_permissions):
                    return True
                else:
                    raise InsufficientPermission
            else:
                return False
        except AttributeError:
            raise InsufficientPermission

    def get_permissions(self, request, view):
        try:
            return getattr(view, "access_token_permissions")
        except AttributeError:
            raise ImproperlyConfigured(
                "Define the access_token_permissions attribute for each method"
            )


class InsufficientPermission(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = {
        "error": True,
        "message": "Insufficient role, scope or permission",
    }
    default_code = "insufficient_permission"
