import collections
from owwatcher import owwatcher
import os
import pytest
import logging

class OWWatcherTest(owwatcher.OWWatcher):
    def __init__(self, monkeypatch, perms_mask, logger, syslog_logger, is_snap=False):
        super().__init__(perms_mask, logger, syslog_logger, is_snap=False)
        self.alert_sent_warning = False
        self.warning_msg = ""
        monkeypatch.setattr(syslog_logger, "warning", self.warning)

        self.alert_sent_info = False
        self.info_msg = ""
        monkeypatch.setattr(syslog_logger, "info", self.info)

    def warning(self, msg):
        self.alert_sent_warning = True
        self.warning_msg = msg

    def info(self, msg):
        self.alert_sent_info = True
        self.info_msg = msg

@pytest.fixture
def owwatcher_object(monkeypatch):
    null_logger = logging.getLogger('owwatcher.null')
    null_logger.addHandler(logging.NullHandler())

    null_syslog_logger = logging.getLogger('owwatcher.null-syslog')
    null_syslog_logger.addHandler(logging.NullHandler)

    return OWWatcherTest(monkeypatch, None, null_logger, null_syslog_logger)

def test_has_interesting_events_false(owwatcher_object):
    interesting_events = {"IN_ATTRIB", "IN_CREATE", "IN_MOVED_TO"}
    received_events = ["IN_DELETE", "IN_ISDIR"]

    assert not owwatcher_object._has_interesting_events(received_events, interesting_events)

def test_has_interesting_events_true(owwatcher_object):
    interesting_events = {"IN_ATTRIB", "IN_CREATE", "IN_MOVED_TO"}

    received_events = ["IN_CREATE", "IN_ISDIR"]
    assert owwatcher_object._has_interesting_events(received_events, interesting_events)

    received_events = ["IN_MOVED_TO"]
    assert owwatcher_object._has_interesting_events(received_events, interesting_events)

def mock_stat(stats):
    for s in stats:
        yield s

def lambda_mock_stat(_, stats):
    try:
        return next(mock_stat(stats))
    except:
        return Stat(st_mode=0o777)

Stat = collections.namedtuple('Stat', 'st_mode')
def patch_stat(monkeypatch, modes):
    stats = map(lambda mode: Stat(st_mode=mode), modes)
    monkeypatch.setattr(os, "stat", lambda _: lambda_mock_stat(_, stats))

def test_is_world_writable_true(monkeypatch, owwatcher_object):
    path = "/tmp/random_dir_kljafl"
    filename = "test_file"

    patch_stat(monkeypatch, [0o006])
    assert owwatcher_object._is_world_writable(path, filename)

    patch_stat(monkeypatch, [0o777])
    assert owwatcher_object._is_world_writable(path, filename)

    patch_stat(monkeypatch, [0o002])
    assert owwatcher_object._is_world_writable(path, filename)

    patch_stat(monkeypatch, [0o666])
    assert owwatcher_object._is_world_writable(path, filename)

def test_is_world_writable_false(monkeypatch, owwatcher_object):
    path = "/tmp/random_dir_kljafl"
    filename = "test_file"

    patch_stat(monkeypatch, [0o004])
    assert not owwatcher_object._is_world_writable(path, filename)

    patch_stat(monkeypatch, [0o770])
    assert not owwatcher_object._is_world_writable(path, filename)

    patch_stat(monkeypatch, [0o641])
    assert not owwatcher_object._is_world_writable(path, filename)

    patch_stat(monkeypatch, [0o665])
    assert not owwatcher_object._is_world_writable(path, filename)

def test_process_event_no_interesting(monkeypatch, owwatcher_object):
    event = (None, ["IN_OPEN", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_dir")
    patch_stat(monkeypatch, [0o777])

    owwatcher_object._process_event("/tmp", event)
    assert not owwatcher_object.alert_sent_warning

def test_process_event_ow_dir(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_dir")
    patch_stat(monkeypatch, [0o002])
    monkeypatch.setattr(os.path, "isdir", lambda _: True)

    owwatcher_object._process_event("/tmp", event)
    assert owwatcher_object.alert_sent_warning
    assert owwatcher_object.warning_msg == "Found world writable directory: /tmp/random_dir_kljafl/a_dir"

def test_process_event_ow_file(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_file")
    patch_stat(monkeypatch, [0o002])
    monkeypatch.setattr(os.path, "isdir", lambda _: False)

    owwatcher_object._process_event("/tmp", event)
    assert owwatcher_object.alert_sent_warning
    assert owwatcher_object.warning_msg == "Found world writable file: /tmp/random_dir_kljafl/a_file"

def test_process_event_perms_mask_file(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_file")
    patch_stat(monkeypatch, [0o750])
    monkeypatch.setattr(os.path, "isdir", lambda _: False)

    owwatcher_object.perms_mask = 0o010
    owwatcher_object._process_event("/tmp", event)
    assert owwatcher_object.alert_sent_warning
    assert owwatcher_object.warning_msg == "Found permissions matching mask 010 on file: /tmp/random_dir_kljafl/a_file"

def test_process_event_perms_mask_directory(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_dir")
    patch_stat(monkeypatch, [0o750])
    monkeypatch.setattr(os.path, "isdir", lambda _: True)

    owwatcher_object.perms_mask = 0o010
    owwatcher_object._process_event("/tmp", event)
    assert owwatcher_object.alert_sent_warning
    assert owwatcher_object.warning_msg == "Found permissions matching mask 010 on directory: /tmp/random_dir_kljafl/a_dir"

def test_process_event_mismatched_mask(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_dir")
    patch_stat(monkeypatch, [0o722])

    owwatcher_object.perms_mask = 0o055
    owwatcher_object._process_event("/tmp", event)
    assert not owwatcher_object.alert_sent_warning

def test_process_event_empty_mask(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_dir")
    patch_stat(monkeypatch, [0o777])

    owwatcher_object.perms_mask = 0o000
    owwatcher_object._process_event("/tmp/", event)
    assert not owwatcher_object.alert_sent_warning

def test_process_event_raise_fnf(monkeypatch, owwatcher_object):
    def raise_(x):
        raise x

    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_dir")
    patch_stat(monkeypatch, [0o777])
    monkeypatch.setattr(os, "stat", lambda _: raise_(FileNotFoundError()))

    try:
        owwatcher_object._process_event("/tmp/", event)
    except:
        assert False

def test_process_event_ow_snap_path(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "%s/tmp/dir1/dir2" % owwatcher.SNAP_HOSTFS_PATH_PREFIX, "a_file")
    patch_stat(monkeypatch, [0o002, 0o002])
    monkeypatch.setattr(os.path, "isdir", lambda _: False)

    owwatcher_object.is_snap = True
    owwatcher_object._process_event(owwatcher.SNAP_HOSTFS_PATH_PREFIX + "/tmp", event)
    assert owwatcher_object.alert_sent_warning
    assert owwatcher_object.warning_msg == "Found world writable file: /tmp/dir1/dir2/a_file"

def test_process_event_directory_protects_ow_file(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/dir1/dir2", "a_file")
    patch_stat(monkeypatch, [0o702, 0o702, 0o700])
    monkeypatch.setattr(os.path, "isdir", lambda _: False)

    owwatcher_object._process_event("/tmp", event)
    assert not owwatcher_object.alert_sent_warning
    assert owwatcher_object.alert_sent_info
    assert owwatcher_object.info_msg == "Found world writable file: /tmp/dir1/dir2/a_file " \
            "-- Vulnerabilities are potentially mitigated as one or more parent " \
            "directories do not have improperly configured permissions"

def test_process_event_directory_protects_ow_file_mask(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/dir1/dir2", "a_file")
    patch_stat(monkeypatch, [0o720, 0o720, 0o700])
    monkeypatch.setattr(os.path, "isdir", lambda _: False)

    owwatcher_object.perms_mask = 0o077
    owwatcher_object._process_event("/tmp", event)
    assert not owwatcher_object.alert_sent_warning
    assert owwatcher_object.alert_sent_info
    assert owwatcher_object.info_msg == "Found permissions matching mask 077 on " \
            "file: /tmp/dir1/dir2/a_file -- Vulnerabilities are potentially " \
            "mitigated as one or more parent directories do not have improperly " \
            "configured permissions"
