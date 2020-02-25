import json
import jwt
import ssl
from datetime import datetime
from jwcrypto import jwk, jws
from six.moves.urllib.request import urlopen
from box import Box
from django.conf import settings
from django.core.cache import cache


def has_valid_token(token):
    kid = jwt.get_unverified_header(token)['kid']
    key = get_key_from_jwks_json(settings.AXIOMS_DOMAIN, kid)
    payload = check_token_validity(token, key)
    if payload:
        return payload
    else:
        return False

def check_token_validity(token, key):
    payload = get_payload_from_token(token, key)
    now = datetime.utcnow().timestamp()
    if payload and (now <= payload.exp) and settings.AXIOMS_AUDIENCE in payload.aud:
        return payload
    else:
        return False

def get_payload_from_token(token, key):
    jwstoken = jws.JWS()
    jwstoken.deserialize(token)
    try:
        jwstoken.verify(key)
        return Box(json.loads(jwstoken.payload))
    except jws.InvalidJWSSignature:
        return None

def check_scopes(provided_scopes, required_scopes):
    if not required_scopes:
        return True

    token_scopes = set(provided_scopes.split())
    scopes = set(required_scopes)
    return len(token_scopes.intersection(scopes)) > 0

def get_key_from_jwks_json(tenant, kid):
    fetcher = CacheFetcher()
    # TODO: Review this later
    # if tenant == settings.PUBLIC_DOMAIN:
    #     tenant = settings.AXIOMS_DOMAIN
    data = fetcher.fetch("https://"+tenant+"/oauth2/.well-known/jwks.json", 600)
    return jwk.JWKSet().from_json(data).get_key(kid)

class CacheFetcher:
    def fetch(self, url, max_age=0):
        # Redis cache
        cached = cache.get('jwks'+url)
        if cached:
            return cached
        # Retrieve and cache
        if settings.URL_LIB_SSL_IGNORE:
            context = ssl._create_unverified_context()
            data = urlopen(url, context=context).read()
        else:
            data = urlopen(url).read()
        cache.set('jwks'+url, data, timeout=max_age)
        return data