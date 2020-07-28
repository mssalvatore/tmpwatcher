from queue import LifoQueue

from tmpwatcher.file_archiver import FileArchiver


# TODO: Consider whether it's worth the hasle to use a DI framework and get rid
#       of this class.
class FileArchiverBuilder:
    def __init__(self, logger, archive_path):
        self.logger = logger
        self.archive_path = archive_path

    def build_file_archiver(self, watch_dir):
        if self.archive_path is None or self.archive_path == "":
            self.logger.debug(
                "No archive path was specified; no files will be archived"
            )
            return FileArchiverBuilder.NOPFileArchiver()

        # Use LIFO queue, because copying anything is better than trying to copy
        # everything and ending up with nothing.
        return FileArchiver(self.logger, self.archive_path, watch_dir, LifoQueue())

    class NOPFileArchiver(FileArchiver):
        def __init__(self):
            pass

        def run(self):
            pass

        def stop(self):
            pass

        def add_event_to_archive_file_queue(self, event_types, event_path, filename):
            pass
