from typing import Callable

import requests


class SessionBuilder:

    def __init__(self):
        self.session = requests.Session()

    def proxies(self, proxies: dict):
        self.session.proxies = proxies

    def verify(self, verify: bool):
        self.session.verify = verify


SessionProvider = Callable[[], requests.Session]


class SessionHolder:

    def __init__(self, session_provider: SessionProvider, **kwargs):
        self.session_provider = session_provider

        super().__init__(**kwargs)

    def session(self) -> requests.Session:

        return self.session_provider()

