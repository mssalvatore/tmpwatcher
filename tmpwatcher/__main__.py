#!/usr/bin/env python3

import argparse
import configparser
import os
import signal
import sys

from tmpwatcher.file_archiver_builder import FileArchiverBuilder
from tmpwatcher.options import Options
from tmpwatcher.syslog_alerter import SyslogAlerter
from tmpwatcher.tmpwatcher import TmpWatcher
from tmpwatcher.tmpwatcher_logger_configurer import TmpWatcherLoggerConfigurer

# Creating null loggers allows pytest test suite to run as logging is not
# necessarily configured for each unit test run.
_LOGGER = TmpWatcherLoggerConfigurer.get_null_logger()
_SYSLOG_LOGGER = TmpWatcherLoggerConfigurer.get_null_logger()

_TMPWATCHER = None


def main():
    global _TMPWATCHER
    try:
        is_snap = check_if_snap()

        (parser, args) = _parse_args(is_snap)
        if args.config_path:
            config = _read_config(args.config_path)
            args = Options.config_to_tuple(config, is_snap)

        options = Options(args, is_snap)
        logger_configurer = TmpWatcherLoggerConfigurer(options)
        configure_logging(options, logger_configurer)
        fab = FileArchiverBuilder(_LOGGER, options.archive_path)
        # TODO: Handle perms_mask default in Options instead of here
        if options.perms_mask is None:
            options.perms_mask = 0o002
        syslog_alerter = SyslogAlerter(
            options.perms_mask, _LOGGER, _SYSLOG_LOGGER, is_snap=is_snap
        )
        syslog_alerter.run()
        _TMPWATCHER = TmpWatcher(
            options.perms_mask, fab, _LOGGER, syslog_alerter, is_snap=is_snap
        )

        register_signal_handlers()
    except Exception as ex:
        print("Error during initialization: %s" % str(ex), file=sys.stderr)
        sys.exit(1)
        # TODO: Attempt to log error with some kind of failsafe logger

    _LOGGER.info("Starting TmpWatcher...")
    _log_config_options(options)

    _TMPWATCHER.run(options.dirs, options.recursive)


def check_if_snap():
    return "SNAP_DATA" in os.environ


def _octal_int(x):
    return int(x, 8)


def _parse_args(is_snap):
    parser = argparse.ArgumentParser(
        description="Watch a directory for newly created world writable "
        "files and directories. Log events to a syslog server.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-c",
        "--config-path",
        action="store",
        help="A config file to read settings from. Command line "
        "arguments override values read from the config file. "
        "If the config file does not exist, tmpwatcher will "
        "log a warning and ignore the specified config file. "
        "NOTE: If a config file is specified, all other "
        "command-line options will be ignored.",
    )
    parser.add_argument(
        "-d",
        "--dirs",
        action="store",
        help="A comma-separated list of directories to watch "
        "for world writable files/dirs",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Set up inotify watches recursively. This can"
        "identify more potential vulnerabilities but will"
        "results in a lot of false positives.",
    )
    parser.add_argument(
        "-m",
        "--perms-mask",
        action="store",
        help="Instead of alerting only on world writable files, "
        "use a mask (e.g. 077) to identify files with "
        "incorrect permissions",
        type=_octal_int,
    )
    parser.add_argument(
        "-a",
        "--archive-path",
        action="store",
        help="A directory where files identified by TmpWatcher "
        "can be archived. If this option is set, TmpWatcher "
        "will *attempt* to copy files that are world writable "
        "or match perms-mask so they can be inspected.",
    )
    parser.add_argument(
        "-p",
        "--syslog-port",
        action="store",
        type=int,
        help="The port that the syslog server is listening on",
    )
    parser.add_argument(
        "-s",
        "--syslog-server",
        action="store",
        help="IP address or hostname of a syslog server",
    )
    parser.add_argument(
        "-t",
        "--tcp",
        action="store_true",
        help="Use TCP instead of UDP to send syslog messages.",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Send output to stdout. This is the default behavior "
        "if a log file is not specified. If a log file is "
        "specified, TmpWatcher will not send output to stdout"
        "unless this flag is set.",
    )
    parser.add_argument("-l", "--log-file", action="store", help="Path to log file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    return parser, args


def _read_config(config_path):
    config = configparser.ConfigParser()
    config.read(config_path)

    return config


def configure_logging(options, logger_configurer):
    global _LOGGER
    global _SYSLOG_LOGGER

    _LOGGER = logger_configurer.get_tmpwatcher_logger()
    _SYSLOG_LOGGER = logger_configurer.get_syslog_logger()


def register_signal_handlers():
    signal.signal(signal.SIGINT, receive_signal)
    signal.signal(signal.SIGTERM, receive_signal)


def receive_signal(signum, stack_frame):
    _LOGGER.debug("Received signal %s" % signal.Signals(signum))
    _LOGGER.info("Cleaning up and exiting")

    if _TMPWATCHER is not None:
        _TMPWATCHER.stop()


def _log_config_options(options):
    _LOGGER.info('Option "dirs": %s', ",".join(options.dirs))
    _LOGGER.info('Option "recursive": %s', options.recursive)
    _LOGGER.info('Option "perms_mask": %s', _format_perms_mask_output(options))
    _LOGGER.info('Option "archive_path": %s', options.archive_path)
    _LOGGER.info('Option "syslog_server": %s', options.syslog_server)
    _LOGGER.info('Option "syslog_port": %s', options.syslog_port)
    _LOGGER.info('Option "protocol": %s', options.protocol)
    _LOGGER.info('Option "log_file": %s', options.log_file)
    _LOGGER.info('Option "debug": %s', options.debug)


def _format_perms_mask_output(options):
    if options.perms_mask is None:
        return "None"

    return "{:03o}".format(options.perms_mask)


if __name__ == "__main__":
    main()
