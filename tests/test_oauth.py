import responses


def test_audience(app_settings):
    from framework.auth.oauth import get_audience
    assert get_audience('hello') == 'http://hello/api'


def test_default_audience(app_settings):
    from framework.auth.oauth import get_audience
    assert get_audience() == 'http://test/api'


@responses.activate
def test_auth_cache(app_settings):
    from framework.auth.oauth import get_service_access_token
    responses.add(
        responses.Response(method=responses.POST, url=app_settings['auth_url'],
                           json=dict(access_token='1', expires_in=86400),
                           status=200))
    responses.add(
        responses.Response(method=responses.POST, url=app_settings['auth_url'],
                           json=dict(access_token='2', expires_in=86400),
                           status=200))
    token_a = get_service_access_token(service_name='test')
    token_b = get_service_access_token(service_name='test')
    assert token_a == token_b


@responses.activate
def test_auth_cache_expiration(app_settings):
    from framework.auth.oauth import get_service_access_token
    responses.add(
        responses.Response(method=responses.POST, url=app_settings['auth_url'],
                           json=dict(access_token='1', expires_in=0), status=200)
    )
    responses.add(
        responses.Response(method=responses.POST, url=app_settings['auth_url'],
                           json=dict(access_token='2', expires_in=300), status=200)
    )
    token_a = get_service_access_token(service_name='test_2')
    token_b = get_service_access_token(service_name='test_2')
    assert token_a != token_b
