#!/usr/bin/env python3

import argparse
import os

DEFAULT_MONITORED_DIR = '/tmp'
DEFAULT_SYSLOG_HOST = '127.0.0.1'
DEFAULT_SYSLOG_PORT = 514

INVALID_PORT_ERROR = "Port must be an integer between 1 and 65535 inclusive."
INVALID_DIR_ERROR = "The directory '%s' does not exist"

def main():
    args = parse_args()

def parse_args():
    parser = argparse.ArgumentParser(
            description="Watch a directory for newly created world writable "\
                    "files and directories. Log events to a syslog server.",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-d', '--dir', action='store', default=DEFAULT_MONITORED_DIR,
                        help='A directory to watch for world writable files/dirs')
    parser.add_argument('-p', '--port', action='store',
                        default=DEFAULT_SYSLOG_PORT, type=int,
                        help='The port that the syslog server is listening on')
    parser.add_argument('-s', '--server', action='store', default=DEFAULT_SYSLOG_HOST,
                        help='IP address or hostname of a syslog server')
    parser.add_argument('-t', '--tcp', action='store_true',
                        help='Use TCP instead of UDP to send syslog messages.')

    args = parser.parse_args()
    try:
        _raise_on_invalid_args(args)
    except (TypeError, ValueError) as err:
        parser.error(str(err))

    return args

def _raise_on_invalid_args(args):
    _raise_on_invalid_port(args.port)
    _raise_on_invalid_dir(args.dir)

def _raise_on_invalid_port(port):
    if not isinstance(port, int):
        raise TypeError(INVALID_PORT_ERROR)

    if port < 1 or port > 65535:
        raise ValueError(INVALID_PORT_ERROR)
    
def _raise_on_invalid_dir(dir):
    if not os.path.isdir(dir):
        raise ValueError(INVALID_DIR_ERROR % dir)

if __name__ == "__main__":
    main()
