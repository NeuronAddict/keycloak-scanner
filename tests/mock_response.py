from typing import Dict, Callable, Any, Union
from unittest.mock import MagicMock

import requests
from requests import HTTPError

from keycloak_scanner.logging.printlogger import PrintLogger



class MockResponse:

    def __init__(self, status_code: Union[int, Callable[..., int]],
                 response: Union[Union[str, dict], Callable[..., Union[str, dict]]] = None,
                 headers=None):
        if headers is None:
            headers = {}
        self.status_code = status_code
        self.response = response
        self.text = response
        self.headers = headers

    def raise_for_status(self):
        if self.status_code > 399:
            raise HTTPError('Mock raise for status')

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

    def __init__(self, response: MockResponse, assertion: Callable[..., bool] = (lambda **kwargs: True),
                 assertion_value: Any = None):
        """

        :param response: mocked response
        :param assertion: assertion that must be true
        :param assertion_value: the assertion message was {assertion_value} == {request args}
        """
        self.assertion = assertion
        self.response = response
        self.assertion_value = assertion_value


class MockSpec:

    def __init__(self, get: Dict[str, RequestSpec] = None, post: Dict[str, RequestSpec] = None):
        if post is None:
            post = {}
        if get is None:
            get = {}
        self.get = get
        self.post = post

    def get_mock_response(self, url, **kwargs) -> MockResponse:

        if url not in self.get:
            raise Exception(f'[make_mock_session] Bad url test (GET) : {url}')
        assert self.get[url].assertion(**kwargs), repr(self.get[url].assertion_value) + ' == ' + repr(kwargs)
        return self.get[url].response

    def post_mock_response(self, url, **kwargs) -> MockResponse:

        if url not in self.post:
            raise Exception(f'[make_mock_session] Bad url test (POST) : {url}')
        assert self.post[url].assertion(**kwargs), repr(self.post[url].assertion_value) + ' == ' + repr(kwargs)
        return self.post[url].response

    def session(self):

        session = requests.Session()
        session.get = MagicMock(side_effect=self.get_mock_response)
        session.post = MagicMock(side_effect=self.post_mock_response)

        return session

    def merge(self, get: Dict[str, RequestSpec] = None, post: Dict[str, RequestSpec] = None):

        if post is None:
            post = {}
        if get is None:
            get = {}

        self.get.update(get)
        self.post.update(post)


def mock_session(get: Dict[str, RequestSpec] = None, post: Dict[str, RequestSpec] = None) -> requests.session():

    if get is None:
        get = {}
    if post is None:
        post = {}
    if post is None:
        post = {}
    if get is None:
        get = {}

    return MockSpec(get=get, post=post).session()
