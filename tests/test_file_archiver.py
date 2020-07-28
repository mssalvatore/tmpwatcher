import collections
import logging
import os
import shutil
import time
from queue import LifoQueue
from unittest.mock import MagicMock

import pytest

from tmpwatcher import file_archiver


class FileArchiverTest(file_archiver.FileArchiver):
    def __init__(self):
        null_logger = logging.getLogger("tmpwatcher.null")
        null_logger.addHandler(logging.NullHandler())
        super().__init__(null_logger, "/fake/archive", "/tmp", LifoQueue(), 0.005)

        self.logger.error = MagicMock()

        self.copy_file_called = False

        self.orig_copy2 = shutil.copy2
        shutil.copy2 = MagicMock()

        self.orig_realpath = os.path.realpath
        os.path.realpath = MagicMock()

    # Need to put original functionality back so future tests aren't using the
    # mocks assigned to shutil and os.path
    def __del__(self):
        super().__del__()
        shutil.copy2 = self.orig_copy2
        os.path.realpath = self.orig_realpath

    def add_event_to_archive_file_queue(self, event_types, event_path, filename):
        aft = self.run()
        super().add_event_to_archive_file_queue(event_types, event_path, filename)
        time.sleep(
            0.01
        )  # add small sleep to ensure queue gets processed before thread stops
        self.stop()

        # Wait for thread to finish to ensure test suite is deterministic
        if aft is not None:
            aft.join()

    def _copy_file(self, event_path, filename):
        self.copy_file_called = True
        return super()._copy_file(event_path, filename)


@pytest.fixture
def fa():
    return FileArchiverTest()


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


def test_umask(monkeypatch, fa):
    # For some reason in python you can't check the umask without setting it.
    current_mask = os.umask(0o777)
    os.umask(current_mask)

    assert current_mask == 0o177


def test_archive_path_is_none(monkeypatch, fa):
    patch_stat(monkeypatch, [0o777])
    fa.archive_path = None
    fa.add_event_to_archive_file_queue(["IN_CLOSE_WRITE"], "/tmp/dir1/dir2", "a_file")

    assert not fa.copy_file_called
    assert not shutil.copy2.called


def test_event_has_is_dir(monkeypatch, fa):
    patch_stat(monkeypatch, [0o777])
    fa.add_event_to_archive_file_queue(
        ["IN_CLOSE_WRITE", "IN_ISDIR"], "/tmp/dir1/dir2", "a_dir"
    )

    assert not fa.copy_file_called
    assert not shutil.copy2.called


def test_src_file_real_path_traversal(monkeypatch, fa):
    patch_stat(monkeypatch, [0o777])
    os.path.realpath.side_effect = ["/home/user/a_file", "/fake/archive"]
    fa.add_event_to_archive_file_queue(["IN_CLOSE_WRITE"], "/tmp/dir1/dir2", "a_file")

    assert not shutil.copy2.called
    assert fa.logger.error.called
    fa.logger.error.assert_called_with(
        "Attempting to archive "
        "/tmp/dir1/dir2/a_file may result in files being written outside "
        "of the archive path. Someone may be attempting something nasty "
        "or extremely unorthodox"
    )


def test_dst_file_real_path_traversal(monkeypatch, fa):
    patch_stat(monkeypatch, [0o777])
    os.path.realpath.side_effect = [
        "/tmp/dir1/dir2/a_file",
        "/different/fake/archive/a_file",
    ]
    fa.add_event_to_archive_file_queue(["IN_CLOSE_WRITE"], "/tmp/dir1/dir2", "a_file")

    assert not shutil.copy2.called
    assert fa.logger.error.called
    fa.logger.error.assert_called_with(
        "Attempting to archive "
        "/tmp/dir1/dir2/a_file may result in files being written outside "
        "of the archive path. Someone may be attempting something nasty "
        "or extremely unorthodox"
    )


def test_copy_successful(monkeypatch, fa):
    patch_stat(monkeypatch, [0o777])
    monkeypatch.setattr(time, "time", lambda: 111.111111)
    os.path.realpath.side_effect = ["/tmp/dir1/dir2/a_file", "/fake/archive/a_file"]
    fa.add_event_to_archive_file_queue(["IN_CLOSE_WRITE"], "/tmp/dir1/dir2", "a_file")

    assert shutil.copy2.called
    shutil.copy2.assert_called_with(
        "/tmp/dir1/dir2/a_file",
        "/fake/archive/a_file.111.111111",
        follow_symlinks=False,
    )
