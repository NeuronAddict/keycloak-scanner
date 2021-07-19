import json
from typing import List

import requests
from requests import Session

from .json_result import JsonResult
from .session_holder import SessionProvider


class WellKnown(JsonResult):

    def __init__(self, realm, **kwargs):
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


class Realm(JsonResult):

    WELL_KNOWN_URL_PATTERN = '{}/auth/realms/{}/.well-known/openid-configuration'

    well_known_ = None

    def get_well_known(self, base_url: str, session: Session) -> WellKnown:

        if not self.well_known_:

            url = self.WELL_KNOWN_URL_PATTERN.format(base_url, self.name)
            r = session.get(url)
            r.raise_for_status()
            self.well_known_ = WellKnown(self, name=self.name, url=url, json=r.json())

        return self.well_known_


class SecurityConsole:

    def __init__(self, realm: Realm, url: str, json: dict, secret: dict = None):
        self.realm = realm
        self.url = url
        self.json = json
        self.secret = secret

    def __hash__(self):
        return hash((self.realm, self.url, json.dumps(self.json), json.dumps(self.secret)))

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
        return hash((self.realm, self.client, self.username, self.password))

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


class NoneSign:

    def __init__(self, realm: Realm):
        self.realm = realm

    def __hash__(self):
        return hash(self.realm)

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.realm)})"

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.realm == other.realm
        return NotImplemented


# TODO : base class for this
class FormPostXSS:

    def __init__(self, realm: Realm):
        self.realm = realm

    def __hash__(self):
        return hash(self.realm)

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.realm)})"

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.realm == other.realm
        return NotImplemented


class Username(str):
    pass


class Password(str):
    pass
