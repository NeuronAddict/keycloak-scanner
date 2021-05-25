from typing import Dict, Callable
from unittest.mock import MagicMock

import requests

from keycloak_scanner.logging.printlogger import PrintLogger


class MockResponse:

    def __init__(self, status_code, response=None, headers=None):
        if headers is None:
            headers = {}
        self.status_code = status_code
        self.response = response
        self.text = response
        self.headers = headers

    def raise_for_status(self):
        if self.status_code > 399:
            raise Exception('Mock raise for status')

    def json(self):
        if isinstance(self.response, dict):
            return self.response
        else:
            raise Exception(f'response spec is not json ({self.response})')


class MockPrintLogger(PrintLogger):

    def __init__(self, **kwargs):
        self.infos = []
        self.verboses = []
        self.warns = []
        super().__init__(**kwargs)

    def info(self, message: str):
        self.infos.append(message)
        super().info(message)

    def verbose(self, message: str, color='grey'):
        self.verboses.append({'message': message, 'color': color})
        super().verbose(message, color)

    def warn(self, message: str):
        self.warns.append(message)
        super().warn(message)


class RequestSpec:

    def __init__(self, response: MockResponse, assertion: Callable[..., bool] = (lambda **kwargs: True)):
        self.assertion = assertion
        self.response = response


def mock_session(get=None, post=None) -> requests.session():

    if post is None:
        post = {}
    if get is None:
        get = {}

    def get_mock_response(url, **kwargs):

        if url not in get:
            raise Exception(f'[make_mock_session] Bad url test (GET) : {url}')
        assert get[url].assertion(**kwargs)
        return get[url].response

    def post_mock_response(url, **kwargs):

        if url not in post:
            raise Exception(f'[make_mock_session] Bad url test (POST) : {url}')
        assert post[url].assertion(**kwargs)
        return post[url].response

    session = requests.Session()
    session.get = MagicMock(side_effect=get_mock_response)
    session.post = MagicMock(side_effect=post_mock_response)

    return session
