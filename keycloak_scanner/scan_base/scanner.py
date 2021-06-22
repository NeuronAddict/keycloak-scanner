import itertools
from typing import TypeVar, Generic, Dict, Any, List, Iterator, Optional, Tuple, Set

from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.logging.vuln_flag import VulnFlag
from .scanner_exceptions import NoneResultException
from .session_holder import SessionHolder
from .wrap import WrapperType, Wrapper

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


class UndefinedMediatorException(Exception):
    pass


class Scanner(Generic[Tco], SessionHolder, PrintLogger):

    def __init__(self, base_url: str, result_type: WrapperType[Tco], needs: List[WrapperType] = None, **kwargs):
        if needs is None:
            needs = []
        self.base_url_ = base_url

        self.mediator = None

        self.status = ScannerStatus(len(needs))
        self.needs = needs
        self.result_type = result_type

        super().__init__(**kwargs)

    def set_mediator(self, mediator):
        self.mediator = mediator
        for need in self.needs:
            self.mediator.subscribe(self, need)

    def base_url(self):
        assert not hasattr(super(), 'base_url')
        return self.base_url_

    def name(self):
        assert not hasattr(super(), 'name')
        return self.__class__.__name__

    # TODO: receive iterable
    def receive(self, value: Wrapper[T]) -> None:

        args = self.status.args(value.wrapper_type.name, value.value())
        if args:
            for scan_kwargs in args:
                self.perform_base(**scan_kwargs)

    def perform_base(self, **kwargs) -> None:

        if self.mediator is None:
            raise UndefinedMediatorException()

        super().verbose(f'Start scanner {self.name()} with ({kwargs})')

        result, vf = self.perform(**kwargs)

        if result is None:
            raise NoneResultException()

        self.mediator.send(self.result_type, result, vf)

    def perform(self, **kwargs) -> (Set[Tco], VulnFlag):
        """
        Perform the scan
        :return: scan result (json)
        """
        raise NotImplementedError()
