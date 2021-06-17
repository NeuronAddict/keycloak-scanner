from typing import List, TypeVar, Dict, Generic

from keycloak_scanner.scanners.json_result import JsonResult


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

    def __repr__(self):
        return f"WellKnown({repr(self.realm)}, name='{self.name}', url='{self.url}', json={self.json})"

    def __eq__(self, other):
        if isinstance(other, WellKnown):
            return self.realm == other.realm and self.url == other.url and self.json == other.json
        return NotImplemented


class WellKnownDict(Dict[str, WellKnown]):
    pass

SimpleType = TypeVar('SimpleType') # bound to type ?
V = TypeVar('V')


class ScannerType(Generic[SimpleType]):

    def __init__(self, name: str, simple_type: SimpleType):
        self.name = name
        self.simple_type = simple_type

    def is_simple_type(self, value: V):
        return self.test(value, self.simple_type)

    def is_list_type(self, value: List[V]):
        if len(value) == 0:
            return True
        return self.is_simple_type(value[0])

    def test(self, a, b):
        return isinstance(a, b)


class SecurityConsole:

    def __init__(self, realm: Realm, url: str, json: dict, secret: dict = None):
        self.realm = realm
        self.url = url
        self.json = json
        self.secret = secret

    def __eq__(self, other):
        if isinstance(other, SecurityConsole):
            return self.realm == other.realm and self.url == other.url and self.json == other.json and self.secret == other.secret
        return NotImplemented

    def __repr__(self):
        return f"SecurityConsoleResult({repr(self.realm)}, '{self.url}', '{self.json}', '{self.secret}')"

class ClientConfig(JsonResult):
    pass


class Client:

    def __init__(self, name: str, url: str, auth_endpoint: str = None, client_registration: ClientConfig = None):
        self.name = name
        self.url = url
        self.auth_endpoint = auth_endpoint
        self.client_registration = client_registration

    def __repr__(self):
        return f"Client({repr(self.name)}, {repr(self.url)}, {repr(self.auth_endpoint)}, {repr(self.client_registration)})"

    def __eq__(self, other):
        if isinstance(other, Client):
            return self.name == other.name \
                   and self.url == other.url \
                   and self.auth_endpoint == other.auth_endpoint \
                   and self.client_registration == other.client_registration
        return NotImplemented


realmType = ScannerType('realm', Realm)

wellKnownType = ScannerType('well_known', WellKnown)

securityConsoleType = ScannerType('security_console', SecurityConsole)

clientType = ScannerType('client_scanner', Client)
