#!/usr/bin/env python3

import inotify.adapters
import inotify.constants as ic
import os
from pathlib import Path
import signal
import threading
import time

# Because the snap package uses the system-files interface, all system files
# are accessible at the path "/var/lib/snapd/hostfs". Since this is cumbersome
# for a user to remember and type whenever they use owwatcher. Detect whether
# or not this application is running as a snap package and prefix the requisite
# path so the user doesn't have to.
SNAP_HOSTFS_PATH_PREFIX = "/var/lib/snapd/hostfs"
VULNERABILITY_MITIGATED_MSG = " -- Vulnerabilities are potentially mitigated as " \
                              "one or more parent directories do not have " \
                              "improperly configured permissions"
DEFAULT_OW_MASK = 0o002

class OWWatcher():
    EVENT_MASK = ic.IN_ATTRIB | ic.IN_CREATE | ic.IN_MOVED_TO | ic.IN_ISDIR
    INTERESTING_EVENTS = {"IN_ATTRIB", "IN_CREATE", "IN_MOVED_TO"}

    def __init__(self, perms_mask, logger, syslog_logger, is_snap=False):
        self.process_events = True
        self.perms_mask = perms_mask
        self.logger = logger
        self.syslog_logger = syslog_logger
        self.is_snap = is_snap

    def run(self, dirs):
        for dir in dirs:
            owwatcher_thread = threading.Thread(target=self._watch_for_world_writable_files, args=(dir,), daemon=True)
            owwatcher_thread.start()

        # TODO: Daemon threads are used because the threads are often blocked
        # waiting on inotify events. Find a non-blocking inotify solution to remove
        # the necessity for this busy loop. Daemon threads are automatically killed
        # after main thread exits.
        while self.process_events:
            time.sleep(1)

    def stop(self,):
        self.process_events = False

    def _watch_for_world_writable_files(self, watch_dir):
        self.logger.info("Setting up inotify watches on %s and its subdirectories" % watch_dir)

        if self.is_snap:
            watch_dir = watch_dir.strip('/')
            watch_dir = os.path.join(SNAP_HOSTFS_PATH_PREFIX, watch_dir)
            self.logger.debug("It was detected that this application is"\
                    " running as a snap. Actual inotify watch set up on"\
                    " dir %s" % watch_dir)

        while True:
            try:
                i = inotify.adapters.InotifyTree(watch_dir, mask=OWWatcher.EVENT_MASK)

                for event in i.event_gen(yield_nones=False):
                    (headers, type_names, event_path, filename) = event

                    if self.is_snap and event_path.startswith(SNAP_HOSTFS_PATH_PREFIX):
                            event_path = event_path[len(SNAP_HOSTFS_PATH_PREFIX):]
                    self.logger.debug("Received event: %s" % "PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(
                                  event_path, filename, type_names))

                    self._process_event(watch_dir, event)
            except FileNotFoundError as fnf:
                msg = "Caught error while adding initial inotify watches on tree [%s]: %s" % (watch_dir, str(fnf))
                self.logger.warning(msg)
            except inotify.adapters.TerminalEventException as tex:
                time.sleep(1) # TODO: Fix this hack for avoiding race condition failure when IN_UNMOUNT event is received
                self.logger.warning("Caught a terminal inotify event (%s). Rebuilding inotify watchers..." % str(tex))

    def _process_event(self, watch_dir, event):
        self.logger.debug("Processing event")
        # '_' variable stands in for "headers", which is not used in this function
        (_, event_types, event_path, filename) = event
        if not self._has_interesting_events(event_types, OWWatcher.INTERESTING_EVENTS):
            self.logger.debug("No relevant event types found")
            return

        if self.perms_mask is None:
            if self._is_world_writable(event_path, filename):
                self.logger.info("Found world writable file/directory. Sending alert.")
                self._send_ow_alert(watch_dir, event_path, filename)
        elif self._check_perms_mask(event_path, filename):
            self.logger.info("Found file matching the permissions mask. Sending alert.")
            self._send_perms_mask_alert(watch_dir, event_path, filename)

    def _has_interesting_events(self, event_types, interesting_events):
        # Converts event_types to a set and takes the intersection of interesting
        # events and received events. If there are any items in the intersection, we
        # know there was at least one interesting event.
        return len(interesting_events.intersection(set(event_types))) > 0

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
