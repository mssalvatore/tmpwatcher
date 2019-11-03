import logging
import logging.handlers
import socket

# This factory class creates and configures owwatcher's loggers
class OWWatcherLoggerConfigurer:
    def __init__(self, debug, syslog_server, syslog_port, log_file):
        self.owwatcher_logger = None
        self.syslog_logger = None

        self._configure_root_logger(debug)
        self._configure_inotify_logger(log_file)
        self._configure_owwatcher_logger(log_file)
        self._configure_syslog_logger(syslog_server, syslog_port)

    def _configure_root_logger(self, debug):
        root_logger = logging.getLogger()

        log_level = logging.DEBUG if debug else logging.INFO
        root_logger.setLevel(log_level)

    def _configure_inotify_logger(self, log_file):
        log_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

        inotify_logger = logging.getLogger('inotify')
        self._configure_file_handler(inotify_logger, log_formatter, log_file)

    def _configure_owwatcher_logger(self, log_file):
        self.owwatcher_logger = logging.getLogger('owwatcher.%s' % __name__)
        log_formatter = logging.Formatter("%(asctime)s - %(module)s - %(levelname)s - %(message)s")

        self._configure_file_handler(self.owwatcher_logger, log_formatter, log_file)

    def _configure_file_handler(self, logger, log_formatter, log_file):
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(log_formatter)
        logger.addHandler(file_handler)

    # Used for logging to stdout
    # Currently dead code but will likely be used in the future
    def _configure_stream_handler(self, logger, log_formatter):
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(log_formatter)
        logger.addHandler(stream_handler)

    class _ContextFilter(logging.Filter):
        def __init__(self):
            self.hostname = socket.gethostname()

        def filter(self, record):
            record.hostname = self.hostname
            return True

    def _configure_syslog_logger(self, syslog_server, syslog_port):
        # The syslog logger must not be a child of the self.owwatcher_logger,
        # otherwise some log messages may be duplicated as self.syslog_logger
        # will inherit self.owwatcher_logger's handlers
        self.syslog_logger = logging.getLogger('owwatcher.syslog')
        log_formatter = logging.Formatter("%(hostname)s - %(module)s - %(levelname)s - %(message)s")

        syslog_handler = logging.handlers.SysLogHandler(address=(syslog_server, syslog_port), socktype=socket.SOCK_DGRAM)
        syslog_handler.setFormatter(log_formatter)
        self.syslog_logger.addFilter(self._ContextFilter())
        self.syslog_logger.addHandler(syslog_handler)

    def get_owwatcher_logger(self):
        return self.owwatcher_logger

    def get_syslog_logger(self):
        return self.syslog_logger

    @staticmethod
    def get_null_logger():
        null_logger = logging.getLogger('owwatcher.null')
        null_logger.addHandler(logging.NullHandler)

        return null_logger

