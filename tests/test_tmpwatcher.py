import collections
import logging
import os
from unittest.mock import MagicMock

import pytest

from tmpwatcher import file_archiver_builder, tmpwatcher
from tmpwatcher.inotify_event_constants import InotifyEventConstants as iec


class MockFileArchiverBuilder(file_archiver_builder.FileArchiverBuilder):
    def __init__(self):
        pass

    def build_file_archiver(self, watch_dir):
        return MagicMock()


class TmpWatcherTest(tmpwatcher.TmpWatcher):
    def __init__(self, monkeypatch, perms_mask, logger, is_snap=False):
        super().__init__(
            perms_mask, MockFileArchiverBuilder(), logger, MagicMock(), is_snap=is_snap
        )

    def _process_event(self, watch_dir, event):
        super()._process_event(watch_dir, event, self._get_new_file_archiver(watch_dir))


@pytest.fixture
def tmpwatcher_object(monkeypatch):
    null_logger = logging.getLogger("tmpwatcher.null")
    null_logger.addHandler(logging.NullHandler())

    return TmpWatcherTest(monkeypatch, 0o002, null_logger)


def test_has_interesting_events_false(tmpwatcher_object):
    interesting_events = {iec.IN_ATTRIB, iec.IN_CREATE, iec.IN_MOVED_TO}
    received_events = [iec.IN_DELETE, iec.IN_ISDIR]

    assert not tmpwatcher_object._has_interesting_events(
        received_events, interesting_events
    )


def test_has_interesting_events_true(tmpwatcher_object):
    interesting_events = {iec.IN_ATTRIB, iec.IN_CREATE, iec.IN_MOVED_TO}

    received_events = [iec.IN_CREATE, iec.IN_ISDIR]
    assert tmpwatcher_object._has_interesting_events(
        received_events, interesting_events
    )

    received_events = [iec.IN_MOVED_TO]
    assert tmpwatcher_object._has_interesting_events(
        received_events, interesting_events
    )


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


def test_should_send_alert_true(monkeypatch, tmpwatcher_object):
    path = "/tmp/random_dir_kljafl"
    filename = "test_file"

    patch_stat(monkeypatch, [0o006])
    assert tmpwatcher_object._should_send_alert(path, filename)

    patch_stat(monkeypatch, [0o777])
    assert tmpwatcher_object._should_send_alert(path, filename)

    patch_stat(monkeypatch, [0o002])
    assert tmpwatcher_object._should_send_alert(path, filename)

    patch_stat(monkeypatch, [0o666])
    assert tmpwatcher_object._should_send_alert(path, filename)


def test_should_send_alert_false(monkeypatch, tmpwatcher_object):
    path = "/tmp/random_dir_kljafl"
    filename = "test_file"

    patch_stat(monkeypatch, [0o004])
    assert not tmpwatcher_object._should_send_alert(path, filename)

    patch_stat(monkeypatch, [0o770])
    assert not tmpwatcher_object._should_send_alert(path, filename)

    patch_stat(monkeypatch, [0o641])
    assert not tmpwatcher_object._should_send_alert(path, filename)

    patch_stat(monkeypatch, [0o665])
    assert not tmpwatcher_object._should_send_alert(path, filename)


def test_process_event_no_interesting(monkeypatch, tmpwatcher_object):
    watch_dir = "/tmp"
    event = (None, [iec.IN_OPEN, iec.IN_DELETE], "/tmp/random_dir_kljafl", "a_dir")
    patch_stat(monkeypatch, [0o777])

    tmpwatcher_object._process_event(watch_dir, event)
    assert not tmpwatcher_object.alerter.add_event_to_alert_queue.called


def test_process_event_ow(monkeypatch, tmpwatcher_object):
    watch_dir = "/tmp"
    event = (None, [iec.IN_CREATE, iec.IN_DELETE], "/tmp/random_dir_kljafl", "a_file")
    patch_stat(monkeypatch, [0o002])

    tmpwatcher_object._process_event(watch_dir, event)
    assert tmpwatcher_object.alerter.add_event_to_alert_queue.called
    tmpwatcher_object.alerter.add_event_to_alert_queue.assert_called_with(
        watch_dir, event[2], event[3]
    )


def test_process_event_perms_mask(monkeypatch, tmpwatcher_object):
    watch_dir = "/tmp"
    event = (None, [iec.IN_CREATE, iec.IN_DELETE], "/tmp/random_dir_kljafl", "a_file")
    patch_stat(monkeypatch, [0o750])

    tmpwatcher_object.perms_mask = 0o010
    tmpwatcher_object._process_event(watch_dir, event)
    assert tmpwatcher_object.alerter.add_event_to_alert_queue.called
    tmpwatcher_object.alerter.add_event_to_alert_queue.assert_called_with(
        watch_dir, event[2], event[3]
    )


def test_process_event_mismatched_mask(monkeypatch, tmpwatcher_object):
    watch_dir = "/tmp"
    event = (None, [iec.IN_CREATE, iec.IN_DELETE], "/tmp/random_dir_kljafl", "a_file")
    patch_stat(monkeypatch, [0o722])

    tmpwatcher_object.perms_mask = 0o055
    tmpwatcher_object._process_event(watch_dir, event)
    assert not tmpwatcher_object.alerter.add_event_to_alert_queue.called


def test_process_event_empty_mask(monkeypatch, tmpwatcher_object):
    event = (None, [iec.IN_CREATE, iec.IN_DELETE], "/tmp/random_dir_kljafl", "a_file")
    patch_stat(monkeypatch, [0o777])

    tmpwatcher_object.perms_mask = 0o000
    tmpwatcher_object._process_event("/tmp/", event)
    assert not tmpwatcher_object.alerter.add_event_to_alert_queue.called


def test_process_event_raise_fnf(monkeypatch, tmpwatcher_object):
    def raise_(x):
        raise x

    event = (None, [iec.IN_CREATE, iec.IN_DELETE], "/tmp/random_dir_kljafl", "a_file")
    patch_stat(monkeypatch, [0o777])
    monkeypatch.setattr(os, "stat", lambda _: raise_(FileNotFoundError()))

    try:
        tmpwatcher_object._process_event("/tmp/", event)
    except Exception:
        assert False


def test_process_event_ow_snap_path(monkeypatch, tmpwatcher_object):
    watch_dir = "%s/tmp" % tmpwatcher.SNAP_HOSTFS_PATH_PREFIX
    event = (None, [iec.IN_CREATE, iec.IN_DELETE], "%s/dir1/dir2" % watch_dir, "a_file")
    patch_stat(monkeypatch, [0o002, 0o002])

    tmpwatcher_object.is_snap = True
    tmpwatcher_object._process_event(watch_dir, event)
    assert tmpwatcher_object.alerter.add_event_to_alert_queue.called
    tmpwatcher_object.alerter.add_event_to_alert_queue.assert_called_with(
        watch_dir, event[2], event[3]
    )


def test_process_event_ow_snap_dir(monkeypatch, tmpwatcher_object):
    watch_dir = "%s/tmp" % tmpwatcher.SNAP_HOSTFS_PATH_PREFIX
    event = (None, [iec.IN_CREATE, iec.IN_DELETE], watch_dir, "dir1")
    patch_stat(monkeypatch, [0o002])

    tmpwatcher_object.is_snap = True
    tmpwatcher_object._process_event(watch_dir, event)
    assert tmpwatcher_object.alerter.add_event_to_alert_queue.called
    tmpwatcher_object.alerter.add_event_to_alert_queue.assert_called_with(
        watch_dir, event[2], event[3]
    )


def test_process_event_default_perms_mask_no_archive_file(
    monkeypatch, tmpwatcher_object
):
    watch_dir = "/tmp"
    event = (None, [iec.IN_CLOSE_WRITE], "/tmp/dir1/dir2", "a_file")
    patch_stat(monkeypatch, [0o700])

    tmpwatcher_object._process_event(watch_dir, event)
    assert len(tmpwatcher_object.file_archivers) == 1
    assert not tmpwatcher_object.file_archivers[
        0
    ].add_event_to_archive_file_queue.called


def test_process_event_archives_file(monkeypatch, tmpwatcher_object):
    watch_dir = "/tmp"
    event = (None, [iec.IN_CREATE, iec.IN_CLOSE_WRITE], "/tmp/dir1/dir2", "a_file")
    patch_stat(monkeypatch, [0o777])

    tmpwatcher_object._process_event(watch_dir, event)
    assert len(tmpwatcher_object.file_archivers) == 1
    assert tmpwatcher_object.file_archivers[0].add_event_to_archive_file_queue.called
