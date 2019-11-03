import collections
from owwatcher import owwatcher
import os
import pytest
import logging

@pytest.fixture
def owwatcher_object():
    null_logger = logging.getLogger('owwatcher.null')
    null_logger.addHandler(logging.NullHandler)

    return owwatcher.OWWatcher(null_logger, null_logger)

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

MockStat = collections.namedtuple('MockStat', 'st_mode')
def mock_stat(monkeypatch, mode):
    ms = MockStat(st_mode=mode)
    monkeypatch.setattr(os, "stat", lambda _: ms)

def test_is_world_writable_true(monkeypatch, owwatcher_object):
    path = "/tmp/random_dir_kljafl"
    filename = "test_file"

    mock_stat(monkeypatch, 0o006)
    assert owwatcher_object._is_world_writable(path, filename)

    mock_stat(monkeypatch, 0o777)
    assert owwatcher_object._is_world_writable(path, filename)

    mock_stat(monkeypatch, 0o002)
    assert owwatcher_object._is_world_writable(path, filename)

    mock_stat(monkeypatch, 0o666)
    assert owwatcher_object._is_world_writable(path, filename)

def test_is_world_writable_false(monkeypatch, owwatcher_object):
    path = "/tmp/random_dir_kljafl"
    filename = "test_file"

    mock_stat(monkeypatch, 0o004)
    assert not owwatcher_object._is_world_writable(path, filename)

    mock_stat(monkeypatch, 0o770)
    assert not owwatcher_object._is_world_writable(path, filename)

    mock_stat(monkeypatch, 0o641)
    assert not owwatcher_object._is_world_writable(path, filename)

    mock_stat(monkeypatch, 0o665)
    assert not owwatcher_object._is_world_writable(path, filename)
