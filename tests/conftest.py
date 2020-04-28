import pytest
import responses
from framework.core.common import generate_random_id

issuer_list = [generate_random_id() for _ in range(3)]

audience_list = [generate_random_id() for _ in range(3)]


@pytest.fixture(scope='module')
def issuers():
    return issuer_list


@pytest.fixture(scope='module')
def audiences():
    return audience_list


@pytest.fixture(scope='module', params=issuer_list)
def issuer(request):
    return request.param


@pytest.fixture(scope='module', params=audience_list)
def audience(request):
    return request.param


@pytest.fixture(scope='session', )
def test_directory():
    import os
    return os.path.abspath(__file__).replace('conftest.py', '')


@pytest.fixture(scope='session', )
def app_settings(test_directory):
    from framework.core.settings import get_app_settings
    import os
    return get_app_settings(env_folder=os.path.join(test_directory, 'mocks/settings'))


@pytest.fixture(scope='session', )
def signing_key(test_directory):
    import os
    import json
    with open(os.path.join(test_directory, 'mocks/signing_key.json'), 'rt') as f:
        key = json.load(f)

    return key


@pytest.fixture(scope='session', )
def public_keys(test_directory):
    import os
    import json
    with open(os.path.join(test_directory, 'mocks/public_keys.json'), 'rt') as f:
        key = json.load(f)

    return key


@pytest.fixture()
def client(test_directory):
    import os
    from framework.core.server import create_server
    app = create_server(spec_dir=os.path.join(test_directory, 'mocks/schemas'))
    return app.app.test_client()


@pytest.fixture()
def valid_access_headers(app_settings, signing_key):
    from framework.auth.oauth import generate_oauth_headers
    from framework.auth.jwt import format_access_token, sign_token
    from framework.core.common import generate_random_id

    payload = format_access_token(
        user=generate_random_id(), machine_token=True, audiences=app_settings['audiences'],
        issuer=app_settings['issuers'][0],
        expiration_seconds=60 * 60,
        scopes=["get:hello"]
    )
    token = sign_token(payload=payload, signing_key=signing_key)

    return generate_oauth_headers(access_token=get_token(token, app_settings))


@pytest.fixture()
def invalid_access_headers(app_settings, issuer, signing_key):
    from framework.auth.oauth import generate_oauth_headers
    from framework.auth.jwt import format_access_token, sign_token
    from framework.core.common import generate_random_id
    payload = format_access_token(
        user=generate_random_id(), machine_token=True, audiences=app_settings['audiences'], issuer=generate_random_id(),
        expiration_seconds=60 * 60,
        scopes=[generate_random_id() for i in range(3)]
    )
    token = sign_token(payload=payload, signing_key=signing_key)

    return generate_oauth_headers(access_token=get_token(token, app_settings))


@pytest.fixture()
def unauthorized_access_headers(app_settings, signing_key):
    from framework.auth.oauth import generate_oauth_headers
    from framework.auth.jwt import format_access_token, sign_token
    from framework.core.common import generate_random_id
    payload = format_access_token(
        user=generate_random_id(), machine_token=True, audiences=app_settings['audiences'],
        issuer=app_settings['issuers'][0],
        expiration_seconds=60 * 60,
        scopes=[generate_random_id() for i in range(3)]
    )
    token = sign_token(payload=payload, signing_key=signing_key)

    return generate_oauth_headers(access_token=get_token(token, app_settings))


@pytest.fixture()
def user_access_headers(app_settings, signing_key):
    from framework.auth.oauth import generate_oauth_headers
    from framework.auth.jwt import format_access_token, sign_token
    from framework.core.common import generate_random_id
    payload = format_access_token(
        user=generate_random_id(), machine_token=False, audiences=app_settings['audiences'],
        issuer=app_settings['issuers'][0],
        expiration_seconds=60 * 60,
        scopes=[]
    )
    token = sign_token(payload=payload, signing_key=signing_key)
    print(payload)
    return generate_oauth_headers(access_token=get_token(token, app_settings))


@responses.activate
def get_token(token, app_settings):
    from framework.auth.oauth import get_service_access_token
    responses.add(
        responses.Response(method=responses.POST, url=app_settings['auth_url'],
                           json=dict(access_token=token, expires_in=86400),
                           status=200))
    return get_service_access_token(service_name='test', refresh=True)
