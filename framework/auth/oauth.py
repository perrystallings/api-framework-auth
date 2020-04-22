__auth_keys__ = None
__tokens__ = dict()


def get_audience(service_name=None) -> str:
    from framework.core.settings import get_app_settings
    app_settings = get_app_settings()
    audience = app_settings['audience_format'].format(service_name)
    return audience


def generate_token_key(service_name, client_id, client_secret):
    from framework.core.common import generate_hash_id
    return generate_hash_id(dict(service_name=service_name, client_id=client_id, client_secret=client_secret))


def check_token_cache(service_name, client_id, client_secret):
    from datetime import datetime
    now = datetime.utcnow()
    key = generate_token_key(service_name=service_name, client_id=client_id, client_secret=client_secret)
    global __tokens__
    if __tokens__.get(key) is not None:
        token = __tokens__[key]['token']
        if TOKENS[key]['expires'] > int(now.utcnow().timestamp()):
            return token
        else:
            return None
    else:
        return None


def cache_token(token_response, service_name, client_id, client_secret):
    from datetime import datetime
    global TOKENS
    now = datetime.utcnow()
    key = generate_token_key(service_name=service_name, client_id=client_id, client_secret=client_secret)
    expiration_time = int(now.timestamp() + token_response['expires_in'] * .8)
    TOKENS[key] = dict(token=token_response['access_token'],
                       expires=expiration_time)
    return token_response['access_token']


def get_auth_keys():
    from framework.core.requests import safe_json_request
    from framework.core.settings import get_app_settings
    app_settings = get_app_settings()
    global __auth_keys__
    if __auth_keys__ is None:
        status_code, js = safe_json_request(method='GET',
                                            url="{0}/.well-known/jwks.json".format(app_settings['auth_domain']))
        if js:
            __auth_keys__ = js['keys']
    return __auth_keys__


def decode_token(token, auth_keys):
    from jose import jwt
    from framework.core.settings import get_app_settings
    import itertools
    app_settings = get_app_settings()

    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    payload = None
    user_token = False
    for key in auth_keys:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
            break
    if rsa_key:
        for audience, issuer in itertools.product(app_settings['audiences'], app_settings['issuers']):
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=["RS256"],
                    audience=audience,
                    issuer=issuer)
            except jwt.JWTError:
                pass
            else:
                break
        if payload['sub'].startswith('auth0'):
            user_token = True
    return user_token, payload


def get_service_access_token(service_name, client_id=None, client_secret=None):
    from framework.core.settings import get_app_settings
    from framework.core.requests import safe_json_request
    app_settings = get_app_settings()
    if not client_id:
        client_id = app_settings['client_id']
    if not client_secret:
        client_secret = app_settings['client_secret']
    token = check_token_cache(service_name=service_name, client_id=client_id, client_secret=client_secret)
    if token is None:
        body = dict(
            client_id=client_id,
            client_secret=client_secret,
            audience=get_audience(service_name=service_name),
            grant_type="client_credentials"
        )

        status_code, js = safe_json_request(
            url=app_settings['auth_url'], method='POST',
            json=body
        )
        if status_code < 300:
            token = cache_token(token_response=js, service_name=service_name, client_id=client_id,
                                client_secret=client_secret)
    return token


def get_user_scopes(user_token, service_name=None):
    from framework.core.requests import safe_json_request, generate_oauth_headers
    from framework.core.settings import get_app_settings
    app_settings = get_app_settings()
    scopes = []
    if service_name is None:
        service_name = app_settings['service_name']
    audience = get_audience(service_name=service_name)
    status_code, js = safe_json_request(
        method='POST',
        url="{0}{1}".format(app_settings['user_service_domain'], app_settings['validate_scopes_path']),
        headers=generate_oauth_headers(
            access_token=user_token
        ),
        json=dict(
            audience=audience,
            scopes=[]
        )
    )
    if status_code == 200:
        scopes = js['response'].get('available_scopes', [])
    return " ".join(scopes)


def verify_token(token):
    from jose import jwt
    from werkzeug.exceptions import Unauthorized
    import six
    keys = get_auth_keys()

    if not keys:
        raise Unauthorized
    try:
        user_token, decoded_token = decode_token(token=token, auth_keys=keys)
    except jwt.JWTError as e:
        six.raise_from(Unauthorized, e)
    else:
        return decoded_token


def handle_token_request(user, body):
    from connexion import request
    from framework.core.settings import get_app_settings
    from framework.core.requests import safe_json_request
    app_settings = get_app_settings()
    js = dict(
        client_id=user,
        client_secret=request.authorization.password,
        audience=get_audience(),
        **body
    )

    status_code, js = safe_json_request(
        url=app_settings['auth_url'], method='POST',
        json=js
    )
    return js, status_code


def verify_auth(username, password, required_scopes=None):
    return {'sub': username, 'scope': ''}
