#!/usr/bin/env python3

import argparse
import inotify.adapters
import inotify.constants as ic
import logging
import os

DEFAULT_MONITORED_DIR = '/tmp'
DEFAULT_SYSLOG_HOST = '127.0.0.1'
DEFAULT_SYSLOG_PORT = 514

INVALID_PORT_ERROR = "Port must be an integer between 1 and 65535 inclusive."
INVALID_DIR_ERROR = "The directory '%s' does not exist"

EVENT_MASK = ic.IN_ATTRIB | ic.IN_CREATE | ic.IN_MOVED_TO | ic.IN_ISDIR
INTERESTING_EVENTS = {"IN_ATTRIB", "IN_CREATE", "IN_MOVED_TO"}

def main():
    args = parse_args()
    detect_ow_files(args.dir)

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

def detect_ow_files(dir):
    while True: # TODO: Break out of this loop
        try:
            i = inotify.adapters.InotifyTree(dir, mask=EVENT_MASK)#, mask=ic.constants.IN_CREATE)
            for event in i.event_gen(yield_nones=False):
                (headers, type_names, path, filename) = event

                print("PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(
                      path, filename, type_names))
                process_event(event)
        except inotify.adapters.TerminalEventException as tex:
            # TODO: Print a useful message
            import time
            time.sleep(1) # TODO: Fix this hack for avoiding race condition failure when IN_UNMOUNT event is detected
            pass

def process_event(event):
    (headers, event_types, path, filename) = event
    if not has_interesting_events(event_types, INTERESTING_EVENTS):
        return

    if is_world_writable(path, filename):
        send_ow_alert(path, filename)


def has_interesting_events(event_types, interesting_events):
    # Converts event_types to a set and takes the intersection of interesting
    # events and received events. If there are any items in the intersection, we
    # know there was at least one interesting event.
    return len(interesting_events.intersection(set(event_types))) > 0

def is_world_writable(path, filename):
    full_path = os.path.join(path, filename)
    status = os.stat(full_path)

    return status.st_mode & 0o002

def send_ow_alert(path, filename):
    print(os.path.join(path, filename) + " IS WORLD WRITABLE")


if __name__ == "__main__":
    main()
