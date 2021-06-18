from keycloak_scanner.scanners.wrap import WrapperType


def test_scanner_type():

    class TestClass:
        pass

    s = WrapperType(TestClass)

    assert s.name == 'test_class'

