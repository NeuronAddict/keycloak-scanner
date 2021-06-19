import json
from typing import List, Dict

import requests

from keycloak_scanner.scanners.json_result import JsonResult
from keycloak_scanner.scanners.session_holder import SessionProvider


class Realm(JsonResult):
    pass


class Realms(List[Realm]):
    pass


class WellKnown(JsonResult):

    def __init__(self, realm: Realm, **kwargs):
        self.realm = realm
        super().__init__(**kwargs)

    def allowed_grants(self) -> List[str]:
        if 'grant_types_supported' in self.json:
            return self.json['grant_types_supported']
        raise Exception('Unable to get allowed grants')

    def __hash__(self):
        return hash((self.realm, self.name, self.url, json.dumps(self.json)))

    def __repr__(self):
        return f"WellKnown({repr(self.realm)}, name='{self.name}', url='{self.url}', json={self.json})"

    def __eq__(self, other):
        if isinstance(other, WellKnown):
            return self.realm == other.realm and self.url == other.url and self.json == other.json
        return NotImplemented


class WellKnownDict(Dict[str, WellKnown]):
    pass


class SecurityConsole:

    def __init__(self, realm: Realm, url: str, json: dict, secret: dict = None):
        self.realm = realm
        self.url = url
        self.json = json
        self.secret = secret

    def __hash__(self):
        return hash((self.realm, self.url, self.json, self.secret))

    def __eq__(self, other):
        if isinstance(other, SecurityConsole):
            return self.realm == other.realm and self.url == other.url and self.json == other.json \
                   and self.secret == other.secret
        return NotImplemented

    def __repr__(self):
        return f"SecurityConsoleResult({repr(self.realm)}, '{self.url}', '{self.json}', '{self.secret}')"


class ClientConfig(JsonResult):
    pass


class Client:

    def __init__(self, name: str, url: str, client_registration: ClientConfig = None):
        self.name = name
        self.url = url
        self.client_registration = client_registration

    def __hash__(self):
        return hash((self.name, self.url, self.client_registration))

    def __repr__(self):
        return f"Client({repr(self.name)}, {repr(self.url)}, " \
               f"{repr(self.client_registration)})"

    def __eq__(self, other):
        if isinstance(other, Client):
            return self.name == other.name \
                   and self.url == other.url \
                   and self.client_registration == other.client_registration
        return NotImplemented


class Credential:

    def __init__(self, realm: Realm, client: Client, username: str, password: str):
        self.realm = realm
        self.client = client
        self.username = username
        self.password = password

    def __hash__(self):
        return hash((self.realm, self.client, self.password))

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.realm)}, {repr(self.client)}, {repr(self.username)}, {repr(self.password)})"

    def __eq__(self, other):
        if isinstance(other, Credential):
            return self.realm == other.realm and self.client == other.client and self.username == other.username \
                   and self.password == other.password
        return NotImplemented

    def get_token(self, session_provider: SessionProvider,
                  weel_known: WellKnown,
                  grant_type='password',
                  client_secret: str = ''):

        r = session_provider().post(weel_known.json['token_endpoint'],
                                   data={
                                       'client_id': self.client.name,
                                       'username': self.username,
                                       'password': self.password,
                                       'grant_type': grant_type,
                                       'client_secret': client_secret
                                   })

        r.raise_for_status()
        res = r.json()
        return res['access_token'], res['refresh_token']


class ClientRegistration(JsonResult):

    def __init__(self, callback_url, **kwargs):
        self.callback_url = callback_url
        super().__init__(**kwargs)

    def __hash__(self):
        return hash((self.callback_url, self.name, self.url, json.dumps(self.json)))

    def __eq__(self, other):
        return isinstance(other, ClientRegistration) and self.callback_url == other.callback_url \
               and super().__eq__(other)

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.callback_url)}, name={repr(self.name)}, " \
               f"url={repr(self.url)}, json={repr(self.json)})"

    def delete(self, session: requests.Session):
        session.delete(self.url, headers={'Authorization': f'Bearer {self.json["registration_access_token"]}'})


class OpenRedirect:

    def __init__(self, realm: Realm, client: Client):
        self.realm = realm
        self.client = client

    def __hash__(self):
        return hash((self.realm, self.client))

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.realm)}, {repr(self.client)})"

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.realm == other.realm and self.client == other.client
        return NotImplemented
