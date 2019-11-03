#!/usr/bin/env python3

import argparse
import collections
import configparser
import inotify.adapters
import inotify.constants as ic
import os
from .owwatcher_logger_configurer import OWWatcherLoggerConfigurer
import signal
import sys
import threading
import time

INVALID_DIR_ERROR = "The directory '%s' does not exist"
INVALID_PORT_ERROR = "Port must be an integer between 1 and 65535 inclusive."
INVALID_PROTOCOL_ERROR = "Unknown protocol '%s'. Valid protocols are 'udp' or 'tcp'."
INVALID_DEBUG_ERROR = "'%s' is not a valid value for the debug option. Valid values are 'True' or 'False'."

EVENT_MASK = ic.IN_ATTRIB | ic.IN_CREATE | ic.IN_MOVED_TO | ic.IN_ISDIR
INTERESTING_EVENTS = {"IN_ATTRIB", "IN_CREATE", "IN_MOVED_TO"}

# Creating null loggers allows pytest test suite to run as logging is not
# necessarily configured for each unit test run.
_LOGGER = OWWatcherLoggerConfigurer.get_null_logger()
_SYSLOG_LOGGER = OWWatcherLoggerConfigurer.get_null_logger()

_PROCESS_EVENTS = True

Options = collections.namedtuple('Options', 'dirs syslog_port syslog_server protocol log_file debug')

def main():
    try:
        (parser, args) = _parse_args()
        config = _read_config(args.config_path)
        options = _merge_args_and_config(args, config)
        configure_logging(options.debug, options.syslog_server, options.syslog_port, options.log_file)
        register_signal_handlers()
    except Exception as ex:
        print("Error during initialization: %s" % str(ex), file=sys.stderr)
        sys.exit(1)

    _LOGGER.info("Starting owwatcher...")
    _log_config_options(options)

    for dir in options.dirs:
        owwatcher_thread = threading.Thread(target=watch_for_world_writable_files, args=(dir,), daemon=True)
        owwatcher_thread.start()

    # TODO: Daemon threads are used because the threads are often blocked
    # waiting on inotify events. Find a non-blocking inotify solution to remove
    # the necessity for this busy loop. Daemon threads are automatically killed
    # after main thread exits.
    while _PROCESS_EVENTS:
        time.sleep(1)

def register_signal_handlers():
    signal.signal(signal.SIGINT, receive_signal)
    signal.signal(signal.SIGTERM, receive_signal)

def receive_signal(signum, stack_frame):
    global _PROCESS_EVENTS

    _LOGGER.debug("Received signal %s" % signal.Signals(signum))
    _LOGGER.info("Cleaning up and exiting")

    _PROCESS_EVENTS = False

def _parse_args():
    default_config_file = _get_default_config_file()

    parser = argparse.ArgumentParser(
            description="Watch a directory for newly created world writable "\
                    "files and directories. Log events to a syslog server.",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-c', '--config-path', action='store', default=default_config_file,
                        help='A config file to read settings from. Command line ' \
                              'arguments override values read from the config file. ' \
                              'If the config file does not exist, owwatcher will ' \
                              'log a warning and ignore the specified config file')
    parser.add_argument('-d', '--dirs', action='store',
                        help='A comma-separated list of directories to watch ' \
                             'for world writable files/dirs')
    parser.add_argument('-p', '--syslog_port', action='store', type=int,
                        help='The port that the syslog server is listening on')
    parser.add_argument('-s', '--syslog-server', action='store',
                        help='IP address or hostname of a syslog server')
    parser.add_argument('-t', '--tcp', action='store_true',
                        help='Use TCP instead of UDP to send syslog messages.')
    parser.add_argument('-l', '--log-file', action='store',
                        help='Path to log file')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')

    args = parser.parse_args()

    return parser, args

def _get_default_config_file():
    return _get_default_file_path('/etc/', 'owwatcher.conf')

def _get_default_log_file():
    return _get_default_file_path('/var/log', 'owwatcher.log')

def _get_default_file_path(default_path, file_name):
    if 'SNAP_DATA' in os.environ:
        return os.path.join(os.getenv('SNAP_DATA'), file_name)

    return os.path.join(default_path, file_name)

def _read_config(config_path):
    config = configparser.ConfigParser()
    config.read(config_path)

    return config

# TODO: Factor this out into it's own Options class. Replace Options named tuple
#       with options class
def _merge_args_and_config(args, config):
    dirs = _merge_dirs_option(args, config, ["/tmp"])
    syslog_port = _merge_syslog_port_option(args, config, 514)
    syslog_server = _merge_syslog_server_option(args, config, "127.0.0.1")
    log_file = _merge_log_file_option(args, config, _get_default_log_file())
    protocol = _merge_protocol_option(args, config, "udp")
    debug = _merge_debug_option(args, config, False)

    options = Options(dirs=dirs, syslog_port=syslog_port, syslog_server=syslog_server,
                      protocol=protocol, log_file=log_file, debug=debug)

    _raise_on_invalid_options(options)

    return options

def _merge_dirs_option(args, config, default):
    return _merge_single_option('dirs', args.dirs, config, default).split(',')

def _merge_syslog_port_option(args, config, default):
    return _merge_single_option('syslog_port', args.syslog_port, config, default)

def _merge_syslog_server_option(args, config, default):
    return _merge_single_option('syslog_server', args.syslog_server, config, default)

def _merge_log_file_option(args, config, default):
    return _merge_single_option('log_file', args.log_file, config, default)

def _merge_single_option(option_name, arg, config, default):
    if arg is not None:
        return arg

    if option_name in config['DEFAULT']:
        return config['DEFAULT'][option_name]

    return default

def _merge_protocol_option(args, config, default):
    if args.tcp:
        return "tcp"

    if 'protocol' in config['DEFAULT']:
        return config['DEFAULT']['protocol'].lower()

    return default

def _merge_debug_option(args, config, default):
    if args.debug:
        return True

    if 'debug' in config['DEFAULT']:
        _raise_on_invalid_debug(config['DEFAULT']['debug'])
        return True if config['DEFAULT']['debug'] == 'True' else False

    return default

def _raise_on_invalid_options(options):
    _raise_on_invalid_syslog_port(options.syslog_port)
    _raise_on_invalid_protocol(options.protocol)

    for dir in options.dirs:
        _raise_on_invalid_dir(dir)

def _raise_on_invalid_syslog_port(syslog_port):
    if not isinstance(syslog_port, int):
        raise TypeError(INVALID_PORT_ERROR)

    if syslog_port < 1 or syslog_port > 65535:
        raise ValueError(INVALID_PORT_ERROR)

def _raise_on_invalid_dir(dir):
    if not os.path.isdir(dir):
        raise ValueError(INVALID_DIR_ERROR % dir)

def _raise_on_invalid_protocol(protocol):
    if protocol not in ('tcp', 'udp'):
        raise ValueError(INVALID_PROTOCOL_ERROR % protocol)

def _raise_on_invalid_debug(debug):
    if debug not in ("True", "False"):
        raise ValueError(INVALID_DEBUG_ERROR % debug)

def configure_logging(debug, syslog_server, syslog_port, log_file):
    global _LOGGER
    global _SYSLOG_LOGGER

    logger_configurer = OWWatcherLoggerConfigurer(debug, syslog_server, syslog_port, log_file)
    _LOGGER = logger_configurer.get_owwatcher_logger()
    _SYSLOG_LOGGER = logger_configurer.get_syslog_logger()

def _log_config_options(options):
    _LOGGER.info('Option "dirs": %s', ','.join(options.dirs))
    _LOGGER.info('Option "syslog_server": %s', options.syslog_server)
    _LOGGER.info('Option "syslog_port": %s', options.syslog_port)
    _LOGGER.info('Option "protocol": %s', options.protocol)
    _LOGGER.info('Option "log_file": %s', options.log_file)
    _LOGGER.info('Option "debug": %s', options.debug)

def watch_for_world_writable_files(dir):
    while True:
        try:
            _LOGGER.info("Setting up inotify watches on %s and its subdirectories" % dir)
            i = inotify.adapters.InotifyTree(dir, mask=EVENT_MASK)
            for event in i.event_gen(yield_nones=False):
                (headers, type_names, path, filename) = event

                _LOGGER.debug("Received event: %s" % "PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(
                              path, filename, type_names))
                process_event(event)
        except inotify.adapters.TerminalEventException as tex:
            time.sleep(1) # TODO: Fix this hack for avoiding race condition failure when IN_UNMOUNT event is received
            _LOGGER.warning("Caught a terminal inotify event (%s). Rebuilding inotify watchers..." % str(tex))

def process_event(event):
    _LOGGER.debug("Processing event")
    # '_' variable stands in for "headers", which is not used in this function
    (_, event_types, path, filename) = event
    if not has_interesting_events(event_types, INTERESTING_EVENTS):
        _LOGGER.debug("No relevant event types found")
        return

    if is_world_writable(path, filename):
        _LOGGER.info("Found world writable file/directory. Sending alert.")
        send_ow_alert(path, filename)


def has_interesting_events(event_types, interesting_events):
    # Converts event_types to a set and takes the intersection of interesting
    # events and received events. If there are any items in the intersection, we
    # know there was at least one interesting event.
    return len(interesting_events.intersection(set(event_types))) > 0

def is_world_writable(path, filename):
    try:
        full_path = os.path.join(path, filename)
        _LOGGER.debug("Checking if %s is world writable" % full_path)

        status = os.stat(full_path)

        return status.st_mode & 0o002
    except (FileNotFoundError)as fnf:
        _LOGGER.debug("File was deleted before its permissions could be checked: %s" % str(fnf))
        return False

def send_ow_alert(path, filename):
    full_path = os.path.join(path, filename)
    file_or_dir = "directory" if os.path.isdir(full_path) else "file"
    msg = "Found world writable %s: %s" % (file_or_dir, full_path)

    _LOGGER.warning(msg)
    _SYSLOG_LOGGER.warning(msg)

if __name__ == "__main__":
    main()
