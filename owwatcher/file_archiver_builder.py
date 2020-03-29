from .file_archiver import FileArchiver
from queue import LifoQueue

# TODO: Consider whether it's worth the hasle to use a DI framework and get rid
#       of this class.
class FileArchiverBuilder():
    def __init__(self, logger, archive_path):
        self.logger = logger
        self.archive_path = archive_path

    def build_file_archiver(self, watch_dir):
        # Use LIFO queue, because copying anything is better than trying to copy
        # everything and ending up with nothing.
        return FileArchiver(self.logger, self.archive_path, watch_dir, LifoQueue())
