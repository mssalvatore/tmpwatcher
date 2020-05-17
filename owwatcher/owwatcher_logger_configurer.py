import logging
import logging.handlers
import socket
import sys

# This factory class creates and configures owwatcher's loggers
class OWWatcherLoggerConfigurer:
    def __init__(self, options):
        self.owwatcher_logger = None
        self.syslog_logger = None

        self._configure_root_logger(options.debug)
        self._configure_inotify_logger(options.log_file, options.stdout)
        self._configure_owwatcher_logger(options.log_file, options.stdout)
        self._configure_syslog_logger(options.syslog_server, options.syslog_port, options.protocol)

    def __del__(self):
        root_logger = logging.getLogger()
        inotify_logger = logging.getLogger('inotify')
        null_logger = OWWatcherLoggerConfigurer.get_null_logger()

        OWWatcherLoggerConfigurer._clean_logger(root_logger)
        OWWatcherLoggerConfigurer._clean_logger(null_logger)
        OWWatcherLoggerConfigurer._clean_logger(inotify_logger)
        OWWatcherLoggerConfigurer._clean_logger(self.owwatcher_logger)
        OWWatcherLoggerConfigurer._clean_logger(self.syslog_logger)

    @staticmethod
    def _clean_logger(logger):
        if logger is None:
            return

        list(map(logger.removeHandler, logger.handlers[:]))
        list(map(logger.removeFilter, logger.filters[:]))
    def _configure_root_logger(self, debug):
        root_logger = logging.getLogger()

        log_level = logging.DEBUG if debug else logging.INFO
        root_logger.setLevel(log_level)

    def _configure_inotify_logger(self, log_file, log_to_stdout):
        inotify_logger = logging.getLogger('inotify')
        log_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

        self._configure_local_logger(inotify_logger, log_formatter, log_file, log_to_stdout)

    def _configure_owwatcher_logger(self, log_file, log_to_stdout):
        self.owwatcher_logger = logging.getLogger('owwatcher.%s' % __name__)
        log_formatter = logging.Formatter("%(asctime)s - %(module)s - %(levelname)s - %(message)s")

        self._configure_local_logger(self.owwatcher_logger, log_formatter, log_file, log_to_stdout)

    def _configure_local_logger(self, logger, log_formatter, log_file, log_to_stdout):
        if log_file:
            self._configure_file_handler(logger, log_formatter, log_file)

        if not log_file or log_to_stdout:
            self._configure_stream_handler(logger, log_formatter)

    def _configure_file_handler(self, logger, log_formatter, log_file):
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(log_formatter)
        logger.addHandler(file_handler)

    def _configure_stream_handler(self, logger, log_formatter):
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(log_formatter)
        logger.addHandler(stream_handler)

    class _ContextFilter(logging.Filter):
        def __init__(self):
            self.hostname = socket.gethostname()

        def filter(self, record):
            record.hostname = self.hostname
            return True

    def _configure_syslog_logger(self, syslog_server, syslog_port, protocol):
        if syslog_server is None or syslog_port is None:
            self.syslog_logger = OWWatcherLoggerConfigurer.get_null_logger()
            return

        # The syslog logger must not be a child of the self.owwatcher_logger,
        # otherwise some log messages may be duplicated as self.syslog_logger
        # will inherit self.owwatcher_logger's handlers
        self.syslog_logger = logging.getLogger('owwatcher.syslog')
        log_formatter = logging.Formatter("%(hostname)s - owwatcher - %(levelname)s - %(message)s")

        socket_type = OWWatcherLoggerConfigurer._get_socket_type_from_protocol_name(protocol)
        syslog_handler = logging.handlers.SysLogHandler(
                address=(syslog_server, syslog_port), socktype=socket_type)

        syslog_handler.setFormatter(log_formatter)
        self.syslog_logger.addFilter(self._ContextFilter())
        self.syslog_logger.addHandler(syslog_handler)

    @staticmethod
    def _get_socket_type_from_protocol_name(protocol):
        if protocol == "tcp":
            return socket.SOCK_STREAM

        if protocol == "udp":
            return socket.SOCK_DGRAM

        raise ValueError("Unexpected protocol '%s'. Valid protocols are " \
                    "'tcp' or 'udp'." % protocol)

    def get_owwatcher_logger(self):
        return self.owwatcher_logger

    def get_syslog_logger(self):
        return self.syslog_logger

    @staticmethod
    def get_null_logger():
        null_logger = logging.getLogger('owwatcher.null')
        if len(null_logger.handlers) < 1:
            null_logger.addHandler(logging.NullHandler())

        return null_logger
