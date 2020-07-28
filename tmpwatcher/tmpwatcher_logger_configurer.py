import logging
import logging.handlers
import socket
import sys


# This factory class creates and configures tmpwatcher's loggers
class TmpWatcherLoggerConfigurer:
    def __init__(self, options):
        self.tmpwatcher_logger = None
        self.syslog_logger = None

        self._configure_root_logger(options.debug)
        self._configure_inotify_logger(options.log_file, options.stdout)
        self._configure_tmpwatcher_logger(options.log_file, options.stdout)
        self._configure_syslog_logger(
            options.syslog_server, options.syslog_port, options.protocol
        )

    def __del__(self):
        root_logger = logging.getLogger()
        inotify_logger = logging.getLogger("inotify")
        null_logger = TmpWatcherLoggerConfigurer.get_null_logger()

        TmpWatcherLoggerConfigurer._clean_logger(root_logger)
        TmpWatcherLoggerConfigurer._clean_logger(null_logger)
        TmpWatcherLoggerConfigurer._clean_logger(inotify_logger)
        TmpWatcherLoggerConfigurer._clean_logger(self.tmpwatcher_logger)
        TmpWatcherLoggerConfigurer._clean_logger(self.syslog_logger)

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
        inotify_logger = logging.getLogger("inotify")
        log_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

        self._configure_local_logger(
            inotify_logger, log_formatter, log_file, log_to_stdout
        )

    def _configure_tmpwatcher_logger(self, log_file, log_to_stdout):
        self.tmpwatcher_logger = logging.getLogger("tmpwatcher.%s" % __name__)
        log_formatter = logging.Formatter(
            "%(asctime)s - %(module)s - %(levelname)s - %(message)s"
        )

        self._configure_local_logger(
            self.tmpwatcher_logger, log_formatter, log_file, log_to_stdout
        )

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
            self.syslog_logger = TmpWatcherLoggerConfigurer.get_null_logger()
            return

        # The syslog logger must not be a child of the self.tmpwatcher_logger,
        # otherwise some log messages may be duplicated as self.syslog_logger
        # will inherit self.tmpwatcher_logger's handlers
        self.syslog_logger = logging.getLogger("tmpwatcher.syslog")
        log_formatter = logging.Formatter(
            "%(hostname)s - tmpwatcher - %(levelname)s - %(message)s"
        )

        socket_type = TmpWatcherLoggerConfigurer._get_socket_type_from_protocol_name(
            protocol
        )
        syslog_handler = logging.handlers.SysLogHandler(
            address=(syslog_server, syslog_port), socktype=socket_type
        )

        syslog_handler.setFormatter(log_formatter)
        self.syslog_logger.addFilter(self._ContextFilter())
        self.syslog_logger.addHandler(syslog_handler)

    @staticmethod
    def _get_socket_type_from_protocol_name(protocol):
        if protocol == "tcp":
            return socket.SOCK_STREAM

        if protocol == "udp":
            return socket.SOCK_DGRAM

        raise ValueError(
            "Unexpected protocol '%s'. Valid protocols are "
            "'tcp' or 'udp'." % protocol
        )

    def get_tmpwatcher_logger(self):
        return self.tmpwatcher_logger

    def get_syslog_logger(self):
        return self.syslog_logger

    @staticmethod
    def get_null_logger():
        null_logger = logging.getLogger("tmpwatcher.null")
        if len(null_logger.handlers) < 1:
            null_logger.addHandler(logging.NullHandler())

        return null_logger
