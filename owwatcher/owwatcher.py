#!/usr/bin/env python3

import inotify.adapters
import inotify.constants as ic
from .inotify_event_constants import InotifyEventConstants as iec
import os
from pathlib import Path
import queue
from queue import LifoQueue
import shutil
import signal
import sys
import threading
import time

class CriticalError(Exception):
    pass

# Because the snap package uses the system-files interface, all system files
# are accessible at the path "/var/lib/snapd/hostfs". Since this is cumbersome
# for a user to remember and type whenever they use owwatcher. Detect whether
# or not this application is running as a snap package and prefix the requisite
# path so the user doesn't have to.
SNAP_HOSTFS_PATH_PREFIX = "/var/lib/snapd/hostfs"
VULNERABILITY_MITIGATED_MSG = " -- Vulnerabilities are potentially mitigated as " \
                              "one or more parent directories do not have " \
                              "improperly configured permissions"
PATH_TRAVERSAL_ERROR = "Attempting to archive %s may result in files being " \
                       "written outside of the archive path. Someone may be " \
                       "attempting something nasty or extremely unorthodox"
DEFAULT_OW_MASK = 0o002
ARCHIVE_UMASK = 0o177

class OWWatcher():
    EVENT_MASK = ic.IN_ATTRIB | ic.IN_CREATE | ic.IN_MOVED_TO | ic.IN_CLOSE_WRITE
    INTERESTING_EVENTS = {iec.IN_ATTRIB, iec.IN_CREATE, iec.IN_MOVED_TO, iec.IN_CLOSE_WRITE}

    def __init__(self, perms_mask, archive_path, logger, syslog_logger, is_snap=False):
        self.process_events = True
        self.perms_mask = perms_mask
        self.archive_path = archive_path
        self.logger = logger
        self.syslog_logger = syslog_logger
        self.is_snap = is_snap
        self.archive_queue_timeout_sec = 2

        # SECURITY: Set the umask so that archived files do not have go+rwx or
        # u+x permissions. Prevents files which may be malicious and placed in
        # /tmp by an attacker from being accidentally executed from the archive
        # directory. It also prevents the contents of archive_path from being
        # read by an attacker. If, for some reason, archive_path's permissions
        # are not strict enough.
        os.umask(ARCHIVE_UMASK)

    def __del__(self):
        self.process_events = False

    def run(self, dirs, recursive):
        for d in dirs:
            self._run_watcher_thread(d, recursive)

        # TODO: Daemon threads are used because the threads are often blocked
        # waiting on inotify events. Find a non-blocking inotify solution to remove
        # the necessity for this busy loop. Daemon threads are automatically killed
        # after main thread exits.
        while self.process_events:
            time.sleep(1)

    def _run_watcher_thread(self, d, recursive):
        owwatcher_thread = threading.Thread(target=self._watch_for_world_writable_files,
                                            args=(d, recursive),
                                            daemon=True)
        owwatcher_thread.start()

    def stop(self):
        self.process_events = False

    def _watch_for_world_writable_files(self, watch_dir, recursive):
        self.logger.info("Setting up inotify watches on %s and its subdirectories" % watch_dir)

        if self.is_snap:
            watch_dir = watch_dir.strip('/')
            watch_dir = os.path.join(SNAP_HOSTFS_PATH_PREFIX, watch_dir)
            self.logger.debug("It was detected that this application is"\
                    " running as a snap. Actual inotify watch set up on"\
                    " dir %s" % watch_dir)

        # Use LIFO queue, because copying anything is better than trying to copy
        # everything and ending up with nothing.
        archive_file_queue = LifoQueue()
        self._run_archive_files(watch_dir, archive_file_queue)

        while True:
            try:
                i = self._setup_inotify_watches(watch_dir, recursive)

                for event in i.event_gen(yield_nones=False):
                    self._process_event(watch_dir, event, archive_file_queue)
            except FileNotFoundError as fnf:
                msg = "Caught error while adding initial inotify watches on tree [%s]: %s" % (watch_dir, str(fnf))
                self.logger.warning(msg)
            except inotify.adapters.TerminalEventException as tex:
                time.sleep(1) # TODO: Fix this hack for avoiding race condition failure when IN_UNMOUNT event is received
                self.logger.warning("Caught a terminal inotify event (%s). Rebuilding inotify watchers..." % str(tex))
            except inotify.calls.InotifyError as iex:
                self.logger.warning("Caught inotify error (%s). Rebuilding inotify watchers..." % str(iex))
            except CriticalError as ce:
                self.logger.critical(str(ce))
                self.stop()
                break
            except Exception as ex:
                self.logger.error("Caught unexpected error (%s). Rebuilding inotify watchers..." % str(ex))

    def _run_archive_files(self, watch_dir, archive_file_queue):
        archive_thread = threading.Thread(target=self._archive_files,
                args=(watch_dir,archive_file_queue,), daemon=True)
        archive_thread.start()

        # only unit tests currently use this return value
        return archive_thread

    def _setup_inotify_watches(self, watch_dir, recursive):
        try:
            if recursive:
                return inotify.adapters.InotifyTree(watch_dir, mask=OWWatcher.EVENT_MASK)
            else:
                i = inotify.adapters.Inotify()
                i.add_watch(watch_dir, mask=OWWatcher.EVENT_MASK)

                return i
        except PermissionError as pe:
            raise CriticalError("Failed to set up inotify watches due to a " \
                    "permissions error. Try running OWWatcher as root. (%s)" % str(pe))

    def _process_event(self, watch_dir, event, archive_file_queue):
        self.logger.debug("Processing event")

        # '_' variable stands in for "headers", which is not used in this function
        (_, event_types, event_path, filename) = event
        self._log_received_event_debug_msg(event_path, filename, event_types)

        if not self._has_interesting_events(event_types, OWWatcher.INTERESTING_EVENTS):
            self.logger.debug("No relevant event types found")
            return

        if self._should_send_alert(watch_dir, event_path, filename):
            archive_file_queue.put((event_types, event_path, filename))
            self._send_alert(watch_dir, event_path, filename)

    def _log_received_event_debug_msg(self, event_path, filename, event_types):
        if self.is_snap and event_path.startswith(SNAP_HOSTFS_PATH_PREFIX):
                event_path = event_path[len(SNAP_HOSTFS_PATH_PREFIX):]
        self.logger.debug("Received event: %s" % "PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(
                      event_path, filename, event_types))

    def _has_interesting_events(self, event_types, interesting_events):
        # Converts event_types to a set and takes the intersection of interesting
        # events and received events. If there are any items in the intersection, we
        # know there was at least one interesting event.
        return len(interesting_events.intersection(set(event_types))) > 0

    def _should_send_alert(self, watch_dir, event_path, filename):
        if self.perms_mask is None:
            return self._is_world_writable(event_path, filename)

        return self._check_perms_mask(event_path, filename)

    def _is_world_writable(self, path, filename):
        self.logger.debug("Checking if file %s at path %s is world writable" % (filename, path))
        return self._check_perms(path, filename, DEFAULT_OW_MASK)

    def _check_perms_mask(self, path, filename):
        self.logger.debug("Checking file %s at path %s against the configured permissions mask" % (filename, path))
        return self._check_perms(path, filename, self.perms_mask)

    def _check_perms(self, path, filename, mask):
        try:
            full_path = os.path.join(path, filename)
            self.logger.debug("Checking permissions of %s against mask %s" % (full_path, "{:03o}".format(mask)))

            status = os.stat(full_path)
            self.logger.debug("Permissions of %s are %s" % (full_path, "{:03o}".format(status.st_mode)))

            return status.st_mode & mask
        except (FileNotFoundError)as fnf:
            self.logger.debug("File was deleted before its permissions could be checked: %s" % str(fnf))
            return False

    def _send_alert(self, watch_dir, event_path, filename):
        # TODO: Send alerts on separate thread.
        if self.perms_mask is None:
            self.logger.info("Found world writable file/directory. Sending alert.")
            self._send_ow_alert(watch_dir, event_path, filename)
        else:
            self.logger.info("Found file matching the permissions mask. Sending alert.")
            self._send_perms_mask_alert(watch_dir, event_path, filename)

    def _send_ow_alert(self, watch_dir, path, filename):
        self._send_syslog_perms_alert(watch_dir, path, filename, "Found world writable")

    def _send_perms_mask_alert(self, watch_dir, path, filename):
        msg = "Found permissions matching mask %s on" % "{:03o}".format(self.perms_mask)
        self._send_syslog_perms_alert(watch_dir, path, filename, msg)

    def _send_syslog_perms_alert(self, watch_dir, path, filename, msg):
        (full_path, event_path) = self._strip_snap_prefix_from_event_path(path, filename)

        file_or_dir = "directory" if os.path.isdir(full_path) else "file"
        msg = "%s %s: %s" % (msg, file_or_dir, event_path)

        mask = DEFAULT_OW_MASK
        if self.perms_mask is not None:
            mask = self.perms_mask

        if not self.all_dirs_in_path_match_mask(watch_dir, path, mask):
            msg = msg + VULNERABILITY_MITIGATED_MSG
            self.logger.info(msg)
            self.syslog_logger.info(msg)
        else:
            self.logger.warning(msg)
            self.syslog_logger.warning(msg)

    def _strip_snap_prefix_from_event_path(self, path, filename):
        full_path = os.path.join(path, filename)

        event_path = full_path
        if self.is_snap and event_path.startswith(SNAP_HOSTFS_PATH_PREFIX):
            event_path = event_path[len(SNAP_HOSTFS_PATH_PREFIX):]

        return (full_path, event_path)

    def all_dirs_in_path_match_mask(self, watch_dir, path, mask):
        if path.rstrip('/') == watch_dir.rstrip('/') :
            return True

        try:
            self.logger.debug("Checking permissions of %s against mask %s" % (path, "{:03o}".format(mask)))
            status = os.stat(path)

            if status.st_mode & mask:
                return self.all_dirs_in_path_match_mask(watch_dir, str(Path(path).parent), mask)
            else:
                return False
        except (FileNotFoundError)as fnf:
            self.logger.debug("File was deleted before its permissions could be checked: %s" % str(fnf))
            return True

    # TODO: Refactor into FileArchiver class
    def _archive_files(self, watch_dir, archive_file_queue):
        while self.process_events:
            try:
                (event_types, event_path, filename) = \
                    archive_file_queue.get(block=True, timeout=self.archive_queue_timeout_sec)
            except queue.Empty:
                continue

            if self.archive_path is None:
                continue

            # No need to save off directories or files that weren't written to
            if self._event_is_archivable(event_types):
                self.logger.debug("Not archiving file. Event types are: %s" % ','.join(event_types))
                continue

            self.logger.debug("Archiving file %s/%s" % (watch_dir, filename))
            self._copy_file(watch_dir, event_path, filename)

    def _event_is_archivable(self, event_types):
        return ((iec.IN_CLOSE_WRITE not in event_types) or (iec.IN_ISDIR in event_types))

    def _copy_file(self, watch_dir, event_path, filename):
        try:
            (file_path, real_file_path, real_copy_path) = \
                self._get_real_file_paths(event_path, filename)

            if (self._directory_traversal_possible(watch_dir, real_file_path, real_copy_path)):
                self.logger.error(PATH_TRAVERSAL_ERROR % file_path)
                return

            dst = "%s.%f" % (real_copy_path, time.time())
            # SECURITY: Make sure follow_symlinks is always false!
            shutil.copy2(real_file_path, dst, follow_symlinks=False)
        except (FileNotFoundError)as fnf:
            self.logger.debug("File was deleted before it could be archived: %s" % str(fnf))
        except Exception as e:
            self.logger.error("An unexpected error occurred while trying to " \
                              "archive file '%s': %s" % (real_file_path, str(e)))

    def _get_real_file_paths(self, event_path, filename):
            file_path = os.path.join(event_path, filename)
            real_file_path = os.path.realpath(file_path)
            real_copy_path = os.path.realpath(os.path.join(self.archive_path, filename))

            return (file_path, real_file_path, real_copy_path)

    def _directory_traversal_possible(self, watch_dir, real_file_path, real_copy_path):
            # This check mostly alleviates my paranoia that an attacker could
            # manipulate this feature into writing arbitrary files to the
            # filesystem. There's still the potential for a TOCTOU race, but I'm
            # not convinced this is really an issue even without this paranoid
            # check, especially if OWWatcher is installed as a snap.
            return ((not real_file_path.startswith(watch_dir)) or
                    (not real_copy_path.startswith(self.archive_path)))
