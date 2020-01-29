from requests import Session


class Request:
    proxy = {}
    verify = True

    @staticmethod
    def request():
        session = Session()
        session.headers = {'User-Agent': 'Keycloak scanner - https://github.com/NeuronAddict/keycloak-scanner'}
        session.proxies = Request.proxy
        session.verify = Request.verify
        return session
