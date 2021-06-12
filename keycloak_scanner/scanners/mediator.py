from typing import TypeVar, List, Dict, Any

from keycloak_scanner.scanners.types import ScannerType

T = TypeVar('T')

class Mediator:

    def __init__(self, **kwargs):
        self.scanners: Dict[str, List[Any]] = {}
        super().__init__(**kwargs)

    def send(self, name: str, value: T) -> None:
        for scanner in self.scanners[name]:
            scanner.receive(name, value)

    def subscribe(self, scanner, scanner_type: ScannerType):
        if scanner_type.name in self.scanners:
            self.scanners[scanner_type.name].append(scanner)
        else:
            self.scanners[scanner_type.name] = [scanner]
