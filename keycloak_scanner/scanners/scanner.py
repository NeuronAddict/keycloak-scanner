import itertools
from typing import TypeVar, Generic, Dict, Any, List, Iterator, Optional, Tuple

from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.mediator import Mediator
from keycloak_scanner.scanners.scanner_exceptions import NoneResultException
from keycloak_scanner.scanners.session_holder import SessionHolder

Tco = TypeVar('Tco', covariant=True)


class TooManyResultsException(BaseException):

    def __init__(self, name: str, value: Any):
        self.name = name
        self.value = value
        super().__init__()


class ScannerStatus:

    def __init__(self, size: int):
        self.size = size
        self.dict: Dict[str, List[Any]] = {}

    def args(self, name: str, value) -> Optional[Iterator[Any]]:
        self.merge(name, value)
        if len(self.dict) == self.size:
            iterables = []
            for name_, value_ in self.dict.items():
                if name_ != name:
                    iterables.append(value_)
                else:
                    iterables.append([value])
            return itertools.product(*iterables)

    def merge(self, name: str, value):
        if name in self.dict:
            self.dict[name].append(value)
        else:
            if len(self.dict) == self.size:
                raise TooManyResultsException(name, value)
            self.dict[name] = [value]


class Scanner(Generic[Tco], SessionHolder, PrintLogger):

    def __init__(self, base_url: str, **kwargs):
        self.base_url_ = base_url
        super().__init__(**kwargs)

    def base_url(self):
        assert not hasattr(super(), 'base_url')
        return self.base_url_

    def name(self):
        assert not hasattr(super(), 'name')
        return self.__class__.__name__

    def init_scan(self):
        super().info(f'Start logger {self.name()}')
        assert not hasattr(super(), 'init_scan')

    def perform(self, **kwargs) -> (Tco, VulnFlag):
        """
        Perform the scan
        :return: scan result (json)
        """
        assert not hasattr(super(), 'perform')
