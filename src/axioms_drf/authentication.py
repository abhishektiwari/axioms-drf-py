from rest_framework import authentication
from rest_framework.exceptions import APIException
from rest_framework import status

class AccessTokenAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
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
            raise UnauthorizedToken
        else:
            if auth_jwt.sub:
                return (auth_jwt.sub, True)
            else:
                raise UnauthorizedToken
        return (None, False)

class IsPostOrIsAccessTokenAuthentication(AccessTokenAuthentication):
    def authenticate(self, request):
        # allow POST requests
        if request.method == 'POST':
            return (None, True)
        else:
            super().authenticate(request)

class MissingAuthorizationHeader(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = {'error': True, 'message': 'Missing Authorization Header'}
    default_code = 'missing_header'

class InvalidAuthorizationBearer(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = {'error': True, 'message': 'Invalid Authorization Bearer'}
    default_code = 'missing_bearer'

class UnauthorizedToken(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = {'error': True, 'message': 'Unauthorized Access - Invalid Token.'}
    default_code = 'missing_header'
