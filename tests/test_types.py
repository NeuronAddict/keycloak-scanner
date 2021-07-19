import pytest

from keycloak_scanner.scan_base.wrap import WrapperType, Wrapper, BadWrappedTypeException
from keycloak_scanner.utils import to_camel_case


def test_scanner_type():

    class TestClass:
        pass

    s = WrapperType(TestClass)

    assert s.name == 'test_class'


def test_shoud_fail_when_bad_type():

    class TestClass:
        pass

    s = WrapperType(TestClass)

    with pytest.raises(BadWrappedTypeException) as e:
        Wrapper(s, 2)

    assert str(e.value) == 'Wrapper error: value 2 not compatible with type TestClass'


def test_camel_case():
    assert to_camel_case('ClassName') == 'class_name'
    assert to_camel_case('WellKnown') == 'well_known'
    assert to_camel_case('Realms') == 'realms'