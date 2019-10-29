#!/usr/bin/env python3

import argparse
import collections
import configparser
import inotify.adapters
import inotify.constants as ic
import logging
import logging.handlers
import os
import signal
import socket
import sys
import time


#DEFAULT_MONITORED_DIR = '/tmp'
#DEFAULT_SYSLOG_HOST = '127.0.0.1'
#DEFAULT_SYSLOG_PORT = 514

INVALID_DIR_ERROR = "The directory '%s' does not exist"
INVALID_PORT_ERROR = "Port must be an integer between 1 and 65535 inclusive."
INVALID_PROTOCOL_ERROR = "Unknown protocol '%s'. Valid protocols are 'udp' or 'tcp'."

EVENT_MASK = ic.IN_ATTRIB | ic.IN_CREATE | ic.IN_MOVED_TO | ic.IN_ISDIR
INTERESTING_EVENTS = {"IN_ATTRIB", "IN_CREATE", "IN_MOVED_TO"}

_LOGGER = logging.getLogger(__name__)
_LOGGER.addHandler(logging.NullHandler)

_SYSLOG_LOGGER = logging.getLogger("%s.%s" % (__name__, "syslog"))
_SYSLOG_LOGGER.addHandler(logging.NullHandler)

_PROCESS_EVENTS = True

DEFAULT_CONFIG_FILE = '/etc/detect_ow.conf'

Options = collections.namedtuple('Options', 'dir port syslog_server protocol debug')

def receive_signal(signum, stack_frame):
    global _PROCESS_EVENTS

    _LOGGER.debug("Received signal %s" % signal.Signals(signum))
    _LOGGER.info("Cleaning up and exiting")

    _PROCESS_EVENTS = False
    time.sleep(1)
    sys.exit(0)

def main():
    global _LOGGER
    try:
        (parser, args) = _parse_args()
        config = _read_config(args.config_path)
        options = _merge_args_and_config(args, config)
    except Exception as ex:
        print("Error: %s" % str(ex), file=sys.stderr)
        sys.exit(1)

    configure_logging(options.debug, options.syslog_server, options.port)
    detect_ow_files(options.dir)

def _parse_args():
    parser = argparse.ArgumentParser(
            description="Watch a directory for newly created world writable "\
                    "files and directories. Log events to a syslog server.",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-c', '--config-path', action='store', default=DEFAULT_CONFIG_FILE,
                        help='A config file to read settings from. Command line ' \
                              'arguments override values read from the config file. ' \
                              'If the config file does not exist, detect_ow will ' \
                              'log a warning and ignore the specified config file')
    parser.add_argument('-d', '--dir', action='store',
                        help='A directory to watch for world writable files/dirs')
    parser.add_argument('-p', '--port', action='store', type=int,
                        help='The port that the syslog server is listening on')
    parser.add_argument('-s', '--syslog-server', action='store',
                        help='IP address or hostname of a syslog server')
    parser.add_argument('-t', '--tcp', action='store_true',
                        help='Use TCP instead of UDP to send syslog messages.')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')

    args = parser.parse_args()

    return parser, args

def _read_config(config_path):
    config = configparser.ConfigParser()
    config.read(config_path)

    return config

def _merge_args_and_config(args, config):
    dir = "/tmp"
    port = 514
    syslog_server = "127.0.0.1"
    protocol = "udp"
    debug = False

    if args.dir is not None:
        dir = args.dir
    elif 'dir' in config['DEFAULT']:
        dir = config['DEFAULT']['dir']

    if args.port is not None:
        port = args.port
    elif 'port' in config['DEFAULT']:
        port = int(config['DEFAULT']['port'])

    if args.syslog_server is not None:
        syslog_server = args.syslog_server
    elif 'syslog_server' in config['DEFAULT']:
        syslog_server = config['DEFAULT']['syslog_server']

    if args.tcp:
        protocol = "tcp"
    elif 'protocol' in config['DEFAULT']:
        protocol = config['DEFAULT']['protocol'].lower()

    _raise_on_invalid_options(port, dir, protocol)

    return Options(dir=dir, port=port, syslog_server=syslog_server, protocol=protocol, debug=args.debug)


def _raise_on_invalid_options(port, dir, protocol):
    _raise_on_invalid_port(port)
    _raise_on_invalid_dir(dir)
    _raise_on_invalid_protocol(protocol)

def _raise_on_invalid_port(port):
    if not isinstance(port, int):
        raise TypeError(INVALID_PORT_ERROR)

    if port < 1 or port > 65535:
        raise ValueError(INVALID_PORT_ERROR)

def _raise_on_invalid_dir(dir):
    if not os.path.isdir(dir):
        raise ValueError(INVALID_DIR_ERROR % dir)

def _raise_on_invalid_protocol(protocol):
    if protocol not in ('tcp', 'udp'):
        raise ValueError(INVALID_PROTOCOL_ERROR % protocol)

class ContextFilter(logging.Filter):
    hostname = socket.gethostname()

    def filter(self, record):
        record.hostname = ContextFilter.hostname
        return True

def configure_logging(debug, server, port):
    configure_root_logger(debug)
    configure_syslog_logger(server, port)

    _LOGGER.removeHandler(logging.NullHandler)

def configure_syslog_logger(server, port):
    log_formatter = logging.Formatter("%(hostname)s - %(module)s - %(levelname)s - %(message)s")

    syslog_handler = logging.handlers.SysLogHandler(address=(server, port), socktype=socket.SOCK_DGRAM)
    syslog_handler.setFormatter(log_formatter)
    _SYSLOG_LOGGER.addFilter(ContextFilter())
    _SYSLOG_LOGGER.addHandler(syslog_handler)

    _SYSLOG_LOGGER.removeHandler(logging.NullHandler)
    #_SYSLOG_LOGGER.removeHandler(stream_handler)

def configure_root_logger(debug):
    root_logger = logging.getLogger()

    log_level = logging.DEBUG if debug else logging.INFO
    root_logger.setLevel(log_level)

    log_formatter = logging.Formatter("%(asctime)s - %(module)s - %(levelname)s - %(message)s")

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(log_formatter)
    root_logger.addHandler(stream_handler)

def detect_ow_files(dir):
    while _PROCESS_EVENTS:
        try:
            _LOGGER.info("Setting up inotify watches on %s and its subdirectories" % dir)
            i = inotify.adapters.InotifyTree(dir, mask=EVENT_MASK)#, mask=ic.constants.IN_CREATE)
            for event in i.event_gen(yield_nones=False):
                if not _PROCESS_EVENTS:
                    break

                (headers, type_names, path, filename) = event

                _LOGGER.debug("Received event: %s" % "PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(
                      path, filename, type_names))
                process_event(event)
        except inotify.adapters.TerminalEventException as tex:
            time.sleep(1) # TODO: Fix this hack for avoiding race condition failure when IN_UNMOUNT event is detected
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
    signal.signal(signal.SIGINT, receive_signal)
    signal.signal(signal.SIGTERM, receive_signal)

    main()
