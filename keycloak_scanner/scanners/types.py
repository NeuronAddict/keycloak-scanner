from typing import List

from keycloak_scanner.scanners.json_result import JsonResult


class Realm(JsonResult):
    pass


class Realms(List[Realm]):
    pass


class ScannerType:

    def __init__(self, name: str, list_type, simple_type):
        self.name = name
        self.list_type = list_type
        self.simple_type = simple_type


RealmType = ScannerType('realm', Realms, Realm)

