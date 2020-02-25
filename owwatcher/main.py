#!/usr/bin/env python3

import argparse
import collections
import configparser
from .options import Options
import os
from .owwatcher_logger_configurer import OWWatcherLoggerConfigurer
from .owwatcher import OWWatcher
import signal
import sys

# Creating null loggers allows pytest test suite to run as logging is not
# necessarily configured for each unit test run.
_LOGGER = OWWatcherLoggerConfigurer.get_null_logger()
_SYSLOG_LOGGER = OWWatcherLoggerConfigurer.get_null_logger()

_OWWATCHER = None

def main():
    global _OWWATCHER
    try:
        is_snap = check_if_snap()

        (parser, args) = _parse_args(is_snap)
        if args.config_path:
            config = _read_config(args.config_path)
            args = Options.config_to_tuple(config, is_snap)

        options = Options(args, is_snap)
        logger_configurer = OWWatcherLoggerConfigurer(options)
        configure_logging(options, logger_configurer)
        _OWWATCHER = OWWatcher(options.perms_mask, options.archive_path,
                               _LOGGER, _SYSLOG_LOGGER, is_snap)

        register_signal_handlers()
    except Exception as ex:
        print("Error during initialization: %s" % str(ex), file=sys.stderr)
        sys.exit(1)
        # TODO: Attempt to log error with some kind of failsafe logger

    _LOGGER.info("Starting owwatcher...")
    _log_config_options(options)

    _OWWATCHER.run(options.dirs, options.recursive)

def check_if_snap():
    return 'SNAP_DATA' in os.environ

def _octal_int(x):
        return int(x, 8)

def _parse_args(is_snap):
    parser = argparse.ArgumentParser(
            description="Watch a directory for newly created world writable "\
                    "files and directories. Log events to a syslog server.",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-c', '--config-path', action='store',
                        help='A config file to read settings from. Command line ' \
                              'arguments override values read from the config file. ' \
                              'If the config file does not exist, owwatcher will ' \
                              'log a warning and ignore the specified config file. ' \
                              'NOTE: If a config file is specified, all other ' \
                              'command-line options will be ignored.')
    parser.add_argument('-d', '--dirs', action='store',
                        help='A comma-separated list of directories to watch ' \
                             'for world writable files/dirs')
    parser.add_argument('-r', '--recursive', action='store_true',
                        help='Set up inotify watches recursively. This can' \
                             'identify more potential vulnerabilities but will' \
                             'results in a lot of false positives.')
    parser.add_argument('-m', '--perms-mask', action='store',
                        help='Instead of alerting only on world writable files, ' \
                             'use a mask (e.g. 077) to identify files with ' \
                             'incorrect permissions', type=_octal_int)
    parser.add_argument('-a', '--archive-path', action='store',
                        help='A directory where files identified by OWWatcher ' \
                             'can be archived. If this option is set, OWWatcher '\
                             'will *attempt* to copy files that are world writable '\
                             'or match perms-mask so they can be inspected.')
    parser.add_argument('-p', '--syslog-port', action='store', type=int,
                        help='The port that the syslog server is listening on')
    parser.add_argument('-s', '--syslog-server', action='store',
                        help='IP address or hostname of a syslog server')
    parser.add_argument('-t', '--tcp', action='store_true',
                        help='Use TCP instead of UDP to send syslog messages.')
    parser.add_argument('--stdout', action='store_true',
                        help='Send output to stdout. This is the default behavior' \
                             'if a log file is not specified. If a log file is ' \
                             'specified, OWWatcher will not send output to stdout' \
                             'unless this flag is set.')
    parser.add_argument('-l', '--log-file', action='store',
                        help='Path to log file')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')

    args = parser.parse_args()

    return parser, args

def _read_config(config_path):
    config = configparser.ConfigParser()
    config.read(config_path)

    return config

def configure_logging(options, logger_configurer):
    global _LOGGER
    global _SYSLOG_LOGGER

    _LOGGER = logger_configurer.get_owwatcher_logger()
    _SYSLOG_LOGGER = logger_configurer.get_syslog_logger()

def register_signal_handlers():
    signal.signal(signal.SIGINT, receive_signal)
    signal.signal(signal.SIGTERM, receive_signal)

def receive_signal(signum, stack_frame):
    _LOGGER.debug("Received signal %s" % signal.Signals(signum))
    _LOGGER.info("Cleaning up and exiting")

    if _OWWATCHER is not None:
        _OWWATCHER.stop()

def _log_config_options(options):
    _LOGGER.info('Option "dirs": %s', ','.join(options.dirs))
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
