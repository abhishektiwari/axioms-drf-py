import logging
import re
from django.core.exceptions import ImproperlyConfigured
from rest_framework.exceptions import APIException
from django.conf import settings
from rest_framework import status
from restfw_composed_permissions.base import (BasePermissionComponent, BaseComposedPermission, And, Or)
from restfw_composed_permissions.generic.components import AllowAll

from .helper import check_scopes

class HasUserGotRightUUID(BasePermissionComponent):
    message = 'Permission Denied'

    def has_permission(self, permission, request, view):
        try:
            if hasattr(request, "resolver_match") and hasattr(request.auth_jwt, "sub"):
                user_uuid = request.resolver_match.kwargs.get("user_uuid")
                org_kwarg = self.get_org_kwarg()
                organization = request.resolver_match.kwargs.get(org_kwarg, False)
                if str(user_uuid) == request.auth_jwt.sub:
                    return True
                else:
                    raise UnauthorizedAccess
            else:
                return False
        except AttributeError:
            raise UnauthorizedAccess

    def get_user_uuid_kwarg(self):
        try:
            return getattr(settings, "AXIOMS_USER_UUID_KWARG")
        except AttributeError:
            raise ImproperlyConfigured(
                "Please set the AXIOMS_USER_UUID_KWARG in your settings."
            )

class HasUserGotRightOrg(BasePermissionComponent):
    message = 'Permission Denied'

    def has_permission(self, permission, request, view):
        try:
            org_kwarg = self.get_org_kwarg()
            organization = request.resolver_match.kwargs.get(org_kwarg, False)
            if organization == request.auth_jwt.org:
                return True
            else:
                return False
        except AttributeError:
            return False
    
    def get_org_kwarg(self):
        try:
            return getattr(settings, "AXIOMS_ORG_KWARG")
        except AttributeError:
            raise ImproperlyConfigured(
                "Please set the AXIOMS_ORG_KWARG in your settings."
            )
class HasAccessTokenScope(BasePermissionComponent):
    message = 'Permission Denied'

    def has_permission(self, permission, request, view):
        try:
            auth_jwt = request.auth_jwt
            access_token_scopes = self.get_scopes(request, view)
            if hasattr(auth_jwt, "scope") and access_token_scopes:
                if check_scopes(auth_jwt.scope, access_token_scopes):
                    return True
                else:
                    raise UnauthorizedAccess
            else:
                return False
        except AttributeError:
            raise UnauthorizedAccess

    def get_scopes(self, request, view):
        try:
            return getattr(view, "access_token_scopes")
        except AttributeError:
            raise ImproperlyConfigured(
                "Define the access_token_scopes attribute for each method"
            )


class UnauthorizedAccess(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = {'error': True, 'message': 'Unauthorized Access - Insufficient permission.'}
    default_code = 'missing_bearer'

class AccessScopeAndUserUUIDPermission(BaseComposedPermission):
    def global_permission_set(self):
        return And(HasAccessTokenScope, HasUserGotRightUUID)

    def object_permission_set(self):
        return AllowAll

class AccessScopeAndUserOrgPermission(BaseComposedPermission):
    def global_permission_set(self):
        return And(HasAccessTokenScope, HasUserGotRightOrg)

    def object_permission_set(self):
        return AllowAll

class AccessScopeAndUserUUIDAndUserOrgPermission(BaseComposedPermission):
    def global_permission_set(self):
        return And(HasAccessTokenScope, HasUserGotRightUUID, HasUserGotRightOrg)

    def object_permission_set(self):
        return AllowAll

class AccessScopePermission(BaseComposedPermission):
    def global_permission_set(self):
        return And(HasAccessTokenScope)

    def object_permission_set(self):
        return AllowAll
