from typing import TypeVar, List, Dict, Any

from keycloak_scanner.scanners.scan_results import ScanResults
from keycloak_scanner.scanners.types import ScannerType

T = TypeVar('T')


class Mediator:

    def __init__(self, **kwargs):
        self.scanners: Dict[str, List[Any]] = {}
        self.scan_results = ScanResults()
        super().__init__(**kwargs)

    def send(self, result_type: ScannerType, value: T) -> None:

        assert result_type.is_list_type(value)

        self.scan_results.add(result_type.name, value)

        if result_type.name in self.scanners:
            for scanner in self.scanners[result_type.name]:
                scanner.receive(result_type, value)

    def subscribe(self, scanner, scanner_type: ScannerType):
        if scanner_type.name in self.scanners:
            self.scanners[scanner_type.name].append(scanner)
        else:
            self.scanners[scanner_type.name] = [scanner]

