import itertools
from typing import TypeVar, Generic, Dict, Any, List, Iterator, Optional, Tuple

from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.mediator import Mediator
from keycloak_scanner.scanners.scanner_exceptions import NoneResultException
from keycloak_scanner.scanners.session_holder import SessionHolder
from keycloak_scanner.scanners.types import ScannerType

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

    def args(self, name: str, value) -> Optional[Iterator[Dict[str, Any]]]:
        self.merge(name, value)
        if len(self.dict) == self.size:
            iterables = []
            names: List[str] = []
            for name_, value_ in self.dict.items():
                names.append(name_)
                if name_ != name:
                    iterables.append(value_)
                else:
                    iterables.append([value])
            return self.convert(names, itertools.product(*iterables))

    def merge(self, name: str, value):
        if name in self.dict:
            self.dict[name].append(value)
        else:
            if len(self.dict) == self.size:
                raise TooManyResultsException(name, value)
            self.dict[name] = [value]

    def convert(self, names: List[str], param: Iterator[Tuple[Any, ...]]) -> Iterator[Dict[str, Any]]:
        results = []
        for tuple_ in param:
            results.append(self.tuple_with_names(names, tuple_))
        return results.__iter__()

    def tuple_with_names(self, names: List[str], tuple_):
        assert len(tuple_) == len(names)
        result = {}
        i = 0
        for name in names:
            result[name] = tuple_[i]
            i += 1
        return result

class InvalidResultTypeException(Exception):
    pass


T = TypeVar('T')


class Scanner(Generic[Tco], SessionHolder, PrintLogger):

    def __init__(self, mediator: Mediator, base_url: str, result_type: ScannerType, needs=None, **kwargs):
        if needs is None:
            needs = []
        self.base_url_ = base_url
        self.mediator = mediator
        self.status = ScannerStatus(len(needs))

        self.result_type = result_type

        for need in needs:
            self.mediator.subscribe(self, need)

        super().__init__(**kwargs)

    def base_url(self):
        assert not hasattr(super(), 'base_url')
        return self.base_url_

    def name(self):
        assert not hasattr(super(), 'name')
        return self.__class__.__name__

    # TODO: receive iterable
    def receive(self, result_type: ScannerType[T], value: T) -> None:
        for scan_kwargs in self.status.args(result_type.name, value):
            self.perform_base(**scan_kwargs)

    def perform_base(self, **kwargs) -> None:

        result, vf = self.perform(**kwargs)

        if result is None:
            raise NoneResultException()

        self.mediator.send(self.result_type, result)

    def perform(self, **kwargs) -> (List[Tco], VulnFlag):
        """
        Perform the scan
        :return: scan result (json)
        """
        raise NotImplementedError()
