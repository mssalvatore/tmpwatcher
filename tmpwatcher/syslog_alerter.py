import os
import queue
import threading
from pathlib import Path
from queue import Queue

SNAP_HOSTFS_PATH_PREFIX = "/var/lib/snapd/hostfs"
VULNERABILITY_MITIGATED_MSG = (
    " -- Vulnerabilities are potentially mitigated as "
    "one or more parent directories do not have "
    "improperly configured permissions"
)


class SyslogAlerter:
    def __init__(
        self,
        perms_mask,
        logger,
        syslog_logger,
        alert_queue_timeout_sec=2,
        is_snap=False,
    ):
        self.perms_mask = perms_mask
        self.logger = logger
        self.syslog_logger = syslog_logger
        self.is_snap = is_snap
        self.alert_queue = Queue()
        self.alert_queue_timeout_sec = alert_queue_timeout_sec

    def run(self):
        self.try_read_queue = True
        alerter_thread = threading.Thread(
            target=self._send_alerts, args=(), daemon=True
        )
        alerter_thread.start()

        # only unit tests currently use this return value
        return alerter_thread

    def stop(self):
        self.try_read_queue = False

    def add_event_to_alert_queue(self, watch_dir, event_path, filename):
        self.alert_queue.put((watch_dir, event_path, filename))

    def _send_alerts(self):
        while self.try_read_queue:
            try:
                (watch_dir, event_path, filename) = self.alert_queue.get(
                    block=True, timeout=self.alert_queue_timeout_sec
                )
            except queue.Empty:
                continue

            self.logger.info("Found file matching the permissions mask. Sending alert.")
            self._send_syslog_alert(watch_dir, event_path, filename)

    def _send_syslog_alert(self, watch_dir, event_path, filename):
        msg = "Found permissions matching mask %s on" % "{:03o}".format(self.perms_mask)
        (full_path, new_event_path) = self._strip_snap_prefix_from_event_path(
            event_path, filename
        )

        file_or_dir = "directory" if os.path.isdir(full_path) else "file"
        msg = "%s %s: %s" % (msg, file_or_dir, new_event_path)

        # TODO: Alerter shouldn't be making this decision. This logic belongs
        #       somewhere else.
        if self.all_dirs_in_path_match_mask(watch_dir, event_path, self.perms_mask):
            self.logger.warning(msg)
            self.syslog_logger.warning(msg)
        else:
            msg = msg + VULNERABILITY_MITIGATED_MSG
            self.logger.info(msg)
            self.syslog_logger.info(msg)

    def _strip_snap_prefix_from_event_path(self, path, filename):
        full_path = os.path.join(path, filename)

        event_path = full_path
        if self.is_snap and event_path.startswith(SNAP_HOSTFS_PATH_PREFIX):
            event_path = event_path[len(SNAP_HOSTFS_PATH_PREFIX) :]

        return (full_path, event_path)

    def all_dirs_in_path_match_mask(self, watch_dir, path, mask):
        if path.rstrip("/") == watch_dir.rstrip("/"):
            return True

        try:
            self.logger.debug(
                "Checking permissions of %s against mask %s"
                % (path, "{:03o}".format(mask))
            )
            status = os.stat(path)

            if status.st_mode & mask:
                return self.all_dirs_in_path_match_mask(
                    watch_dir, str(Path(path).parent), mask
                )

            return False
        except (FileNotFoundError) as fnf:
            self.logger.debug(
                "File was deleted before its permissions could be checked: %s"
                % str(fnf)
            )
            return True
