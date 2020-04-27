import pytest


@pytest.fixture(scope='session', )
def test_folder():
    import os
    return os.path.abspath(__file__).replace('conftest.py', '')


@pytest.fixture(scope='session', )
def app_settings(test_folder):
    from framework.core.settings import get_app_settings
    import os
    return get_app_settings(env_folder=os.path.join(test_folder, 'mocks/settings'))


@pytest.fixture(scope='session', )
def signing_key(test_folder):
    import os
    import json
    with open(os.path.join(test_folder, 'mocks/signing_key.json'), 'rt') as f:
        key = json.load(f)

    return key


@pytest.fixture(scope='session', )
def public_keys(test_folder):
    import os
    import json
    with open(os.path.join(test_folder, 'mocks/public_keys.json'), 'rt') as f:
        key = json.load(f)

    return key
