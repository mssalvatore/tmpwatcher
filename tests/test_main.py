from tmpwatcher import __main__ as main


def test_check_if_snap_true(monkeypatch):
    monkeypatch.setenv("SNAP_DATA", "/var/snap/TESTING")
    assert main.check_if_snap()


def test_check_if_snap_false(monkeypatch):
    monkeypatch.delenv("SNAP_DATA", raising=False)
    assert not main.check_if_snap()
