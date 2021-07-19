import pytest

from keycloak_scanner.scan_base.scanner import ScannerStatus, TooManyResultsException


def test_status():
    status = ScannerStatus(3)

    status.args('machin', 2)
    status.args('machin', 4)

    status.args('truc', 'test')
    status.args('truc', 'test2')

    assert list(status.args('bidule', True)) == [{'machin': 2, 'truc': 'test', 'bidule': True},
                                                 {'machin': 2, 'truc': 'test2', 'bidule': True},
                                                 {'machin': 4, 'truc': 'test', 'bidule': True},
                                                 {'machin': 4, 'truc': 'test2', 'bidule': True}]


def test_should_fail_when_add_too_many_args():
    status = ScannerStatus(2)

    status.args('machin', 2)
    status.args('machin', 4)

    status.args('truc', 'test')
    status.args('truc', 'test2')

    with pytest.raises(TooManyResultsException) as e:
        status.args('bidule', True)

    assert e.value.name == 'bidule'
    assert e.value.value is True
