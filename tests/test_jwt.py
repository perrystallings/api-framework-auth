import pytest
from framework.core.common import generate_random_id


@pytest.fixture(scope='module')
def claims(audience, issuer):
    from framework.auth.jwt import format_access_token
    from framework.core.common import generate_random_id

    return format_access_token(
        user=generate_random_id(), machine_token=True, audiences=[audience], issuer=issuer, expiration_seconds=60 * 60,
        scopes=[generate_random_id() for i in range(3)]
    )


@pytest.fixture(scope='module')
def future_token(claims, audience, issuer, signing_key):
    from datetime import datetime, timedelta
    from framework.auth.jwt import sign_token
    from copy import deepcopy
    claims = deepcopy(claims)
    claims['iat'] = int((datetime.fromtimestamp(claims['iat']) + timedelta(days=1)).timestamp())
    claims['exp'] = int((datetime.fromtimestamp(claims['exp']) + timedelta(days=1)).timestamp())
    token = sign_token(payload=claims, signing_key=signing_key)
    return token


@pytest.fixture(scope='module')
def expired_token(claims, audience, issuer, signing_key):
    from datetime import datetime, timedelta
    from framework.auth.jwt import sign_token
    from copy import deepcopy
    claims = deepcopy(claims)
    claims['iat'] = int((datetime.fromtimestamp(claims['iat']) - timedelta(days=1)).timestamp())
    claims['exp'] = int((datetime.fromtimestamp(claims['exp']) - timedelta(days=1)).timestamp())
    token = sign_token(payload=claims, signing_key=signing_key)
    return token


@pytest.fixture(scope='module')
def signed_token(claims, audience, issuer, signing_key):
    from framework.auth.jwt import sign_token
    token = sign_token(payload=claims, signing_key=signing_key)
    return token


def test_decode_token(claims, public_keys, signed_token, audiences, issuers):
    from framework.auth.jwt import decode_token
    user_token, decoded_token = decode_token(token=signed_token, audiences=audiences, issuers=issuers,
                                             auth_keys=public_keys['keys'])
    assert not user_token
    assert claims == decoded_token


def test_invalid_issuer(signed_token, public_keys, audiences):
    from framework.auth.jwt import decode_token
    from jose.exceptions import JWTError
    with pytest.raises(JWTError):
        decode_token(
            token=signed_token, audiences=audiences, issuers=[generate_random_id()],
            auth_keys=public_keys['keys']
        )


def test_invalid_audience(signed_token, public_keys, issuers):
    from framework.auth.jwt import decode_token
    from jose.exceptions import JWTError
    with pytest.raises(JWTError):
        decode_token(token=signed_token, audiences=[generate_random_id()], issuers=issuers,
                     auth_keys=public_keys['keys'])


def test_expired_token(expired_token, public_keys, audiences, issuers):
    from framework.auth.jwt import decode_token
    from jose.exceptions import ExpiredSignatureError
    with pytest.raises(ExpiredSignatureError):
        decode_token(
            token=expired_token, audiences=audiences, issuers=issuers,
            auth_keys=public_keys['keys']
        )


def test_future_token(future_token, public_keys, audiences, issuers):
    from framework.auth.jwt import decode_token
    from jose.exceptions import JWTSignatureError
    with pytest.raises(JWTSignatureError):
        decode_token(
            token=future_token, audiences=audiences, issuers=issuers,
            auth_keys=public_keys['keys']
        )
