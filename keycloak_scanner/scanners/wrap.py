from enum import Enum
from typing import Generic, TypeVar, List

from keycloak_scanner.scanners.types import Realm, WellKnown, SecurityConsole, Client, Credential
from keycloak_scanner.utils import to_camel_case


SimpleType = TypeVar('SimpleType')
V = TypeVar('V')


class WrapperType(Generic[SimpleType]):

    def __init__(self, simple_type: SimpleType):
        self.name = to_camel_case(simple_type.__class__.__name__)
        self.simple_type = simple_type


class Wrapper(Generic[SimpleType]):

    def __init__(self, wrapper_type: WrapperType[SimpleType], value: SimpleType):
        self.wrapper_type: WrapperType[SimpleType] = wrapper_type
        self.value_ = value

    def value(self) -> SimpleType:
        return self.value


class WrapTypes:

    REALM_TYPE = WrapperType(Realm)

    WELL_KNOWN_TYPE = WrapperType(WellKnown)

    SECURITY_CONSOLE_TYPE = WrapperType(SecurityConsole)

    CLIENT_TYPE = WrapperType(Client)

    CREDENTIAL_TYPE = WrapperType(Credential)
