import collections
from owwatcher import owwatcher
import os
import pytest
import logging

class OWWatcherTest(owwatcher.OWWatcher):
    def __init__(self, monkeypatch, perms_mask, logger, syslog_logger, is_snap=False):
        super().__init__(perms_mask, logger, syslog_logger, is_snap=False)
        self.alert_sent = False
        self.warning_msg = ""
        monkeypatch.setattr(syslog_logger, "warning", self.warning)

    def warning(self, msg):
        self.alert_sent = True
        self.warning_msg = msg

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

Stat = collections.namedtuple('Stat', 'st_mode')
def patch_stat(monkeypatch, mode):
    stat = Stat(st_mode=mode)
    monkeypatch.setattr(os, "stat", lambda _: stat)

def test_is_world_writable_true(monkeypatch, owwatcher_object):
    path = "/tmp/random_dir_kljafl"
    filename = "test_file"

    patch_stat(monkeypatch, 0o006)
    assert owwatcher_object._is_world_writable(path, filename)

    patch_stat(monkeypatch, 0o777)
    assert owwatcher_object._is_world_writable(path, filename)

    patch_stat(monkeypatch, 0o002)
    assert owwatcher_object._is_world_writable(path, filename)

    patch_stat(monkeypatch, 0o666)
    assert owwatcher_object._is_world_writable(path, filename)

def test_is_world_writable_false(monkeypatch, owwatcher_object):
    path = "/tmp/random_dir_kljafl"
    filename = "test_file"

    patch_stat(monkeypatch, 0o004)
    assert not owwatcher_object._is_world_writable(path, filename)

    patch_stat(monkeypatch, 0o770)
    assert not owwatcher_object._is_world_writable(path, filename)

    patch_stat(monkeypatch, 0o641)
    assert not owwatcher_object._is_world_writable(path, filename)

    patch_stat(monkeypatch, 0o665)
    assert not owwatcher_object._is_world_writable(path, filename)

def test_process_event_no_interesting(monkeypatch, owwatcher_object):
    event = (None, ["IN_OPEN", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_dir")
    patch_stat(monkeypatch, 0o777)

    owwatcher_object._process_event(event)
    assert not owwatcher_object.alert_sent

def test_process_event_ow_dir(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_dir")
    patch_stat(monkeypatch, 0o002)
    monkeypatch.setattr(os.path, "isdir", lambda _: True)

    owwatcher_object._process_event(event)
    assert owwatcher_object.alert_sent
    assert owwatcher_object.warning_msg == "Found world writable directory: /tmp/random_dir_kljafl/a_dir"

def test_process_event_ow_file(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_file")
    patch_stat(monkeypatch, 0o002)
    monkeypatch.setattr(os.path, "isdir", lambda _: False)

    owwatcher_object._process_event(event)
    assert owwatcher_object.alert_sent
    assert owwatcher_object.warning_msg == "Found world writable file: /tmp/random_dir_kljafl/a_file"

def test_process_event_perms_mask_file(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_file")
    patch_stat(monkeypatch, 0o750)
    monkeypatch.setattr(os.path, "isdir", lambda _: False)

    owwatcher_object.perms_mask = 0o010
    owwatcher_object._process_event(event)
    assert owwatcher_object.alert_sent
    assert owwatcher_object.warning_msg == "Found permissions matching mask 010 on file: /tmp/random_dir_kljafl/a_file"

def test_process_event_perms_mask_directory(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_dir")
    patch_stat(monkeypatch, 0o750)
    monkeypatch.setattr(os.path, "isdir", lambda _: True)

    owwatcher_object.perms_mask = 0o010
    owwatcher_object._process_event(event)
    assert owwatcher_object.alert_sent
    assert owwatcher_object.warning_msg == "Found permissions matching mask 010 on directory: /tmp/random_dir_kljafl/a_dir"

def test_process_event_mismatched_mask(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_dir")
    patch_stat(monkeypatch, 0o722)

    owwatcher_object.perms_mask = 0o055
    owwatcher_object._process_event(event)
    assert not owwatcher_object.alert_sent

def test_process_event_empty_mask(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_dir")
    patch_stat(monkeypatch, 0o777)

    owwatcher_object.perms_mask = 0o000
    owwatcher_object._process_event(event)
    assert not owwatcher_object.alert_sent

def test_process_event_raise_fnf(monkeypatch, owwatcher_object):
    def raise_(x):
        raise x

    event = (None, ["IN_CREATE", "IN_DELETE"], "/tmp/random_dir_kljafl", "a_dir")
    patch_stat(monkeypatch, 0o777)
    monkeypatch.setattr(os, "stat", lambda _: raise_(FileNotFoundError()))

    try:
        owwatcher_object._process_event(event)
    except:
        assert False

def test_process_event_ow_snap_path(monkeypatch, owwatcher_object):
    event = (None, ["IN_CREATE", "IN_DELETE"], "%s/tmp/random_dir_kljafl" % owwatcher.SNAP_HOSTFS_PATH_PREFIX, "a_file")
    patch_stat(monkeypatch, 0o002)
    monkeypatch.setattr(os.path, "isdir", lambda _: False)

    owwatcher_object.is_snap = True
    owwatcher_object._process_event(event)
    assert owwatcher_object.alert_sent
    assert owwatcher_object.warning_msg == "Found world writable file: /tmp/random_dir_kljafl/a_file"
