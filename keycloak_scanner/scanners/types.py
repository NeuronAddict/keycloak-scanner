from typing import List, TypeVar

from keycloak_scanner.scanners.json_result import JsonResult


class Realm(JsonResult):
    pass


class Realms(List[Realm]):
    pass


T = TypeVar('T')


class ScannerType:

    def __init__(self, name: str, list_type, simple_type):
        self.name = name
        self.list_type = list_type
        self.simple_type = simple_type

    def is_simple_type(self, value: T):
        return isinstance(value, self.simple_type)

    def is_list_type(self, value: T):
        return isinstance(value, self.list_type)


RealmType = ScannerType('realm', Realms, Realm)
