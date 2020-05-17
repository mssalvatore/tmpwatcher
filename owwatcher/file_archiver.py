from owwatcher.inotify_event_constants import InotifyEventConstants as iec
import os
import queue
import shutil
import threading
import time

ARCHIVE_UMASK = 0o177
PATH_TRAVERSAL_ERROR = "Attempting to archive %s may result in files being " \
                       "written outside of the archive path. Someone may be " \
                       "attempting something nasty or extremely unorthodox"

class FileArchiver():
    def __init__(self, logger, archive_path, watch_dir, archive_queue, archive_queue_timeout_sec=2):
        self.logger = logger
        self.archive_path = archive_path
        self.watch_dir = watch_dir
        self.archive_queue = archive_queue
        self.archive_queue_timeout_sec = archive_queue_timeout_sec

        # SECURITY: Set the umask so that archived files do not have go+rwx or
        # u+x permissions. Prevents files which may be malicious and placed in
        # /tmp by an attacker from being accidentally executed from the archive
        # directory. It also prevents the contents of archive_path from being
        # read by an attacker. If, for some reason, archive_path's permissions
        # are not strict enough.
        self.orig_umask = os.umask(ARCHIVE_UMASK)

    def __del__(self):
        os.umask(self.orig_umask)

    def run(self):
        self.try_read_queue = True
        archive_thread = threading.Thread(target=self._archive_files,
                args=(), daemon=True)
        archive_thread.start()

        # only unit tests currently use this return value
        return archive_thread

    def stop(self):
        self.try_read_queue = False

    def add_event_to_archive_file_queue(self, event_types, event_path, filename):
        self.archive_queue.put((event_types, event_path, filename))

    def _archive_files(self):
        while self.try_read_queue:
            try:
                (event_types, event_path, filename) = \
                    self.archive_queue.get(block=True, timeout=self.archive_queue_timeout_sec)
            except queue.Empty:
                continue

            # TODO: This should never happen. Raise TypeError in constructor instead.
            if self.archive_path is None:
                continue

            # No need to save off directories or files that weren't written to
            if self._event_is_archivable(event_types):
                self.logger.debug("Not archiving file. Event types are: %s" % ','.join(event_types))
                continue

            self.logger.debug("Archiving file %s/%s" % (self.watch_dir, filename))
            self._copy_file(event_path, filename)

    # TODO: Archiver really shouldn't be making this decision. Put this somewhere else.
    def _event_is_archivable(self, event_types):
        return ((iec.IN_CLOSE_WRITE not in event_types) or (iec.IN_ISDIR in event_types))

    def _copy_file(self, event_path, filename):
        try:
            (file_path, real_file_path, real_copy_path) = \
                self._get_real_file_paths(event_path, filename)

            if (self._directory_traversal_possible(real_file_path, real_copy_path)):
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

    def _directory_traversal_possible(self, real_file_path, real_copy_path):
            # This check mostly alleviates my paranoia that an attacker could
            # manipulate this feature into writing arbitrary files to the
            # filesystem. There's still the potential for a TOCTOU race, but I'm
            # not convinced this is really an issue even without this paranoid
            # check, especially if OWWatcher is installed as a snap.
            return ((not real_file_path.startswith(self.watch_dir)) or
                    (not real_copy_path.startswith(self.archive_path)))
