from enum import Enum
from typing import Generic, TypeVar, List

from keycloak_scanner.scanners.types import Realm, WellKnown, SecurityConsole, Client, Credential, ClientRegistration, \
    OpenRedirect
from keycloak_scanner.utils import to_camel_case


SimpleType = TypeVar('SimpleType')
V = TypeVar('V')


class BadWrappedTypeException(Exception):

    def __init__(self, t: type, value):
        self.t = t
        self.value = value
        super().__init__(f'Wrapper error: value {value} not compatible with type {t.__name__}')


class WrapperType(Generic[SimpleType]):

    def __init__(self, simple_type: type):
        self.name = to_camel_case(simple_type.__name__)
        self.simple_type = simple_type

    def check(self, value):
        if not isinstance(value, self.simple_type):
            raise BadWrappedTypeException(self.simple_type, value)


class Wrapper(Generic[SimpleType]):

    def __init__(self, wrapper_type: WrapperType[SimpleType], value: SimpleType):
        self.wrapper_type: WrapperType[SimpleType] = wrapper_type
        self.wrapper_type.check(value)
        self.value_ = value

    def value(self) -> SimpleType:
        return self.value_


class WrapperTypes:

    REALM_TYPE = WrapperType(Realm)

    WELL_KNOWN_TYPE = WrapperType(WellKnown)

    SECURITY_CONSOLE_TYPE = WrapperType(SecurityConsole)

    CLIENT_TYPE = WrapperType(Client)

    CREDENTIAL_TYPE = WrapperType(Credential)

    CLIENT_REGISTRATION = WrapperType(ClientRegistration)

    OPEN_REDIRECT = WrapperType(OpenRedirect)
