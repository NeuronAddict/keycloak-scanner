import pytest

from keycloak_scanner.scanners.wrap import WrapperType, Wrapper, BadWrappedTypeException


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
