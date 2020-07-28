import collections
import logging
import os
import time
from unittest.mock import MagicMock

from tmpwatcher import syslog_alerter


class SyslogAlerterTest(syslog_alerter.SyslogAlerter):
    def __init__(self, perms_mask, is_snap):
        null_logger = logging.getLogger("tmpwatcher.null")
        null_logger.addHandler(logging.NullHandler())
        super().__init__(perms_mask, null_logger, MagicMock(), 0.005, is_snap)

    def add_event_to_alert_queue(self, watch_dir, event_path, filename):
        alerter_thread = self.run()
        super().add_event_to_alert_queue(watch_dir, event_path, filename)
        time.sleep(
            0.01
        )  # add small sleep to ensure queue gets processed before thread stops
        self.stop()

        # Wait for thread to finish to ensure test suite is deterministic
        if alerter_thread is not None:
            alerter_thread.join()


def mock_stat(stats):
    for s in stats:
        yield s


def lambda_mock_stat(_, stats):
    try:
        return next(mock_stat(stats))
    except Exception:
        return Stat(st_mode=0o777)


Stat = collections.namedtuple("Stat", "st_mode")


def patch_stat(monkeypatch, modes):
    stats = map(lambda mode: Stat(st_mode=mode), modes)
    monkeypatch.setattr(os, "stat", lambda _: lambda_mock_stat(_, stats))


def test_send_warning_alert(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda _: True)
    at = SyslogAlerterTest(0o002, False)
    at.add_event_to_alert_queue("/tmp", "/tmp", "test")

    assert not at.syslog_logger.info.called
    assert at.syslog_logger.warning.called


def test_send_info_alert(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda _: True)
    patch_stat(monkeypatch, [0o700])
    at = SyslogAlerterTest(0o002, False)
    at.add_event_to_alert_queue("/tmp", "/tmp/d1", "test")

    assert not at.syslog_logger.warning.called
    assert at.syslog_logger.info.called


def test_send_alert_file(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda _: False)
    at = SyslogAlerterTest(0o002, False)
    at.add_event_to_alert_queue("/tmp", "/tmp", "test")

    at.syslog_logger.warning.assert_called_with(
        "Found permissions matching mask 002 on file: /tmp/test"
    )


def test_send_alert_directory(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda _: True)
    at = SyslogAlerterTest(0o002, False)
    at.add_event_to_alert_queue("/tmp", "/tmp", "test")

    at.syslog_logger.warning.assert_called_with(
        "Found permissions matching mask 002 on directory: /tmp/test"
    )


def test_send_alert_mask(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda _: True)
    at = SyslogAlerterTest(0o372, False)
    at.add_event_to_alert_queue("/tmp", "/tmp", "test")

    at.syslog_logger.warning.assert_called_with(
        "Found permissions matching mask 372 on directory: /tmp/test"
    )


def test_vulnerability_mitigated_alert(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda _: False)
    patch_stat(monkeypatch, [0o777, 0o700])
    at = SyslogAlerterTest(0o002, False)
    at.add_event_to_alert_queue("/tmp", "/tmp/dir1/dir2", "a_file")

    assert not at.syslog_logger.warning.called
    assert at.syslog_logger.info.called
    at.syslog_logger.info.assert_called_with(
        "Found permissions "
        "matching mask 002 on file: /tmp/dir1/dir2/a_file -- "
        "Vulnerabilities are potentially mitigated as one or more "
        "parent directories do not have improperly configured "
        "permissions"
    )


def test_snap_prefix_stripped(monkeypatch):
    monkeypatch.setattr(os.path, "isdir", lambda _: False)
    at = SyslogAlerterTest(0o002, True)
    at.add_event_to_alert_queue(
        syslog_alerter.SNAP_HOSTFS_PATH_PREFIX + "/tmp",
        syslog_alerter.SNAP_HOSTFS_PATH_PREFIX + "/tmp",
        "test",
    )

    at.syslog_logger.warning.assert_called_with(
        "Found permissions matching mask 002 on file: /tmp/test"
    )
    pass
