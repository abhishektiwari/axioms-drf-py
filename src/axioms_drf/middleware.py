from django.utils.deprecation import MiddlewareMixin
import jwt
from jwt.exceptions import DecodeError
from django.conf import settings
from .helper import has_valid_token, get_key_from_jwks_json


class AccessTokenMiddleware(MiddlewareMixin):
    def process_request(self, request):
        header_name = "Authorization"
        token_prefix = "bearer"
        request.auth_jwt = None
        request.missing_auth_header = False
        request.invalid_bearer_token = False

        try:
            settings.AXIOMS_DOMAIN
            settings.AXIOMS_AUDIENCE
        except AttributeError as e:
            raise Exception(
                "🔥🔥  {}. Please set AXIOMS_DOMAIN, AXIOMS_AUDIENCE in your settings.".format(
                    e
                )
            )

        auth_header = request.headers.get(header_name, None)
        if auth_header is None:
            request.missing_auth_header = True
        else:
            try:
                bearer, _, token = auth_header.partition(" ")
                if bearer.lower() == token_prefix and token != "":
                    payload = has_valid_token(token)
                    request.auth_jwt = payload
                else:
                    request.invalid_bearer_token = True
            except (ValueError, AttributeError, DecodeError):
                request.invalid_bearer_token = True
