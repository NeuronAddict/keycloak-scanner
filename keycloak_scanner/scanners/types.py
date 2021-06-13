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


RealmType = ScannerType('realm', Realm)


wellKnownType = ScannerType('well_known', WellKnown)
