from rest_framework import authentication
from rest_framework.exceptions import APIException
from django.conf import settings
from rest_framework import status


class HasValidAccessToken(authentication.BaseAuthentication):
    def authenticate(self, request):
        # Allow OPTIONS request without access token
        if request.method == 'OPTIONS':
            return (None, True)
        auth_jwt = request.auth_jwt
        missing_auth_header = request.missing_auth_header
        invalid_bearer_token = request.invalid_bearer_token
        if missing_auth_header is True:
            raise MissingAuthorizationHeader
        if invalid_bearer_token is True:
            raise InvalidAuthorizationBearer
        if auth_jwt is False:
            raise UnauthorizedAccess
        else:
            if auth_jwt.sub:
                return (auth_jwt.sub, True)
            else:
                raise UnauthorizedAccess
        return (None, False)

    def authenticate_header(self, request):
        return "Bearer realm='{}', error='unauthorized_access', error_description='Invalid access token'".format(
            settings.AXIOMS_DOMAIN
        )

class IsAccessTokenAuthenticated(HasValidAccessToken):
    def authenticate(self, request):
        super().authenticate(request)

class IsAnyPostOrIsAccessTokenAuthenticated(HasValidAccessToken):
    def authenticate(self, request):
        # Allow POST requests without access token
        if request.method == 'POST':
            return (None, True)
        else:
            super().authenticate(request)

class IsAnyGetOrIsAccessTokenAuthenticated(HasValidAccessToken):
    def authenticate(self, request):
        # Allow GET requests without access token
        if request.method == 'GET':
            return (None, True)
        else:
            super().authenticate(request)

class MissingAuthorizationHeader(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = {"error": True, "message": "Missing Authorization Header"}
    default_code = "missing_header"


class InvalidAuthorizationBearer(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = {"error": True, "message": "Invalid Authorization Bearer"}
    default_code = "missing_bearer"


class UnauthorizedAccess(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = {"error": True, "message": "Invalid access token."}
    default_code = "unauthorized_access"
