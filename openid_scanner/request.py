from requests import Session


class Request:
    proxy = {}

    @staticmethod
    def request():
        session = Session()
        session.headers = {'User-Agent': 'Keycloak scanner'}
        session.proxies = Request.proxy
        return session
