# TmpWatcher

<p align="center">
	<a href="https://github.com/mssalvatore/tmpwatcher/blob/master/LICENSE">
		<img src="https://img.shields.io/github/license/mssalvatore/tmpwatcher" alt="GitHub license">
	</a>
	<img src="https://img.shields.io/github/v/tag/mssalvatore/tmpwatcher" alt="GitHub tag (latest by date)">
	<a href="https://travis-ci.org/mssalvatore/tmpwatcher">
		<img src="https://travis-ci.org/mssalvatore/tmpwatcher.svg?branch=master" alt="Build Status">
	</a>
	<a href="https://codecov.io/gh/mssalvatore/tmpwatcher">
		<img src="https://codecov.io/gh/mssalvatore/tmpwatcher/branch/master/graph/badge.svg" alt="codecov">
	</a>
	<img alt="CodeFactor Grade" src="https://img.shields.io/codefactor/grade/github/mssalvatore/tmpwatcher">
	<a href="https://github.com/mssalvatore/tmpwatcher/issues">
		<img src="https://img.shields.io/github/issues/mssalvatore/tmpwatcher" alt="GitHub issues">
	</a>
	<img src="https://img.shields.io/github/issues-pr/mssalvatore/tmpwatcher" alt="GitHub pull requests">
	<img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/mssalvatore/tmpwatcher">
	<a href="https://snapcraft.io/tmpwatcher">
		<img src="https://snapcraft.io//tmpwatcher/badge.svg" alt="tmpwatcher">
	</a>
	<a href="https://www.python.org/">
		<img src="https://img.shields.io/badge/Made%20with-Python-1f425f.svg" alt="made-with-python">
	</a>
	<a href="http://makeapullrequest.com">
		<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome">
	</a>
	<a href="https://www.firsttimersonly.com/">
		<img src="https://img.shields.io/badge/first--timers--only-friendly-blue.svg?style=flat-square" alt="first-timers-only">
	</a>
</p>

TmpWatcher detects when world-writable directories or files are created in a
user-specified directory. This is useful for passively discovering information
disclosure, symlink race, or TOCTOU vulnerabilities.

## Description

TmpWatcher uses [inotify](http://man7.org/linux/man-pages/man7/inotify.7.html) to
monitor a directory of your choosing (usually `/tmp`). If any world-writable files
or directories are created in the monitored directory, a notification is logged
and/or sent via the syslog protocol to a syslog server of your choosing. This is
useful for passively discovering information disclosure, symlink race, or TOCTOU
vulnerabilities. Instead of reading source code in search of vulnerabilities,
simply configure TmpWatcher and go about your business. You can investigate any
alerts TmpWatcher creates to see if they qualify as vulnerabilities.

"A symlink race is a kind of software security vulnerability that results from
a program creating files in an insecure manner. A malicious user can create
a symbolic link to a file not otherwise accessible to him or her. When the
privileged program creates a file of the same name as the symbolic link, it
actually creates the linked-to file instead, possibly inserting content desired
by the malicious user (see example below), or even provided by the malicious
user (as input to the program)."
https://en.wikipedia.org/wiki/Symlink_race

Time-of-check to time-of-use (TOCTOU) vulnerabilities are the result of race
conditions that occur between the time a software checks the status of a
resource (in this case, a file or directory) and the time the software actually
uses the resource. One common way that TOCTOU vulnerabilities are manifested is
in world-writable files or directories within `/tmp`. If software creates
world-writable files within `/tmp`, a malicious user could potentially create
symlinks or otherwise manipulate the world-writable files in order to cross some
security boundary. For an example of how this attack might work, see
http://www.cis.syr.edu/~wedu/Teaching/IntrCompSec/LectureNotes_New/Race_Condition.pdf

For a discussion on how to safely create and use files in `/tmp`, see
https://www.netmeister.org/blog/mktemp.html.

This tool is **not** intended to detect any kind of malware or intrusion.
Rather, it is a vulnerability research tool which alerts a researcher of
potential information disclosure, symlink race or TOCTOU vulnerabilities as the
researcher goes about their daily activities. In this way, the researcher takes
a passive approach to discovering these vulnerabilities, rather than a more
active approach (e.g.  code audits.)

## Installation

### snap

This project can be installed by using snap:

`snap install tmpwatcher`

### pip

This project can be installed using pip:

`pip3 install --user .`

### virtualenv

This project can be installed into a python virtual environment:

```
$> virtualenv venv
$> source venv/bin/activate
$> pip3 install .
$> deactivate
```

## Running TmpWatcher

See "Usage" or run `tmpwatcher --help` for a description of
available command line arguments.

### Usage

```
usage: tmpwatcher [-h] [-c CONFIG_PATH] [-d DIRS] [-r] [-m PERMS_MASK]
                 [-a ARCHIVE_PATH] [-p SYSLOG_PORT] [-s SYSLOG_SERVER] [-t]
                 [--stdout] [-l LOG_FILE] [--debug]

Watch a directory for newly created world writable files and directories. Log
events to a syslog server.

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_PATH, --config-path CONFIG_PATH
                        A config file to read settings from. Command line
                        arguments override values read from the config file.
                        If the config file does not exist, tmpwatcher will log
                        a warning and ignore the specified config file. NOTE:
                        If a config file is specified, all other command-line
                        options will be ignored. (default: None)
  -d DIRS, --dirs DIRS  A comma-separated list of directories to watch for
                        world writable files/dirs (default: None)
  -r, --recursive       Set up inotify watches recursively. This canidentify
                        more potential vulnerabilities but willresults in a
                        lot of false positives. (default: False)
  -m PERMS_MASK, --perms-mask PERMS_MASK
                        Instead of alerting only on world writable files, use
                        a mask (e.g. 077) to identify files with incorrect
                        permissions (default: None)
  -a ARCHIVE_PATH, --archive-path ARCHIVE_PATH
                        A directory where files identified by TmpWatcher can be
                        archived. If this option is set, TmpWatcher will
                        *attempt* to copy files that are world writable or
                        match perms-mask so they can be inspected. (default:
                        None)
  -p SYSLOG_PORT, --syslog-port SYSLOG_PORT
                        The port that the syslog server is listening on
                        (default: None)
  -s SYSLOG_SERVER, --syslog-server SYSLOG_SERVER
                        IP address or hostname of a syslog server (default:
                        None)
  -t, --tcp             Use TCP instead of UDP to send syslog messages.
                        (default: False)
  --stdout              Send output to stdout. This is the default behaviorif
                        a log file is not specified. If a log file is
                        specified, TmpWatcher will not send output to
                        stdoutunless this flag is set. (default: False)
  -l LOG_FILE, --log-file LOG_FILE
                        Path to log file (default: None)
  --debug               Enable debug logging (default: False)

```

### Configuration Files

Options can be loaded from a config file if TmpWatcher is invoked with the
`--config-path` option.  An example config file can be found at
`./tmpwatcher/tmpwatcher-default.conf`.

### Run directly

TmpWatcher can be run directly from this repository by running `python3 -m tmpwatcher`

### If installed as a snap

If installed as a snap, TmpWatcher can be run in the background as a daemon or in
the foreground. You can enable and disable the TmpWatcher daemon by running `snap
start --enable tmpwatcher` and `snap stop --disable tmpwatcher`.

You can invoke `tmpwatcher` directly as long as `/snap/bin` is in your $PATH.

The TmpWatcher daemon loads its settings from
`/var/snap/tmpwatcher/current/tmpwatcher.conf`. Configuration and log files are
located at `/var/snap/tmpwatcher/current/`.

### If installed with pip

If this project has been installed using pip, you can simply invoke
`tmpwatcher`, assuming the installed script is in your $PATH.

### If installed with virtualenv

If this project has been installed into a virtualenv, it can be run by
performing the following steps:

```
$> source venv/bin/activate
$> tmpwatcher
$> deactivate
```

### Tips and Notes

1. This tool must be run as root if you want to observe `/tmp` with the
   "recursive" option set.

1. Many programs do not consider permissions at all when writing files to
`/tmp/`. In these cases, your [umask](https://en.wikipedia.org/wiki/Umask) will
determine what permissions the files are created with. This means that a
properly configured umask can mitigate  potential vulnerabilities in many
applications. It also means that, in these cases, TmpWatcher may not be effective
in identifying potential vulnerabilities. There are two ways to remedy this
shortcoming:

    i. Use the `--perms-mask` option to specify permissions other than `o+w`
    that should raise alerts. For example, if your umask is set to 027, setting
    `--perms-mask` to 050 (or, even better, 077), can help identify potential
    vulnerabilities that have been mitigated by a properly configured umask.
	Note that the `perms_mask` option can also be added to the config file (e.g.
	`perms_mask=077`)

    ii. Set your umask to be more permissive (i.e. `umask 0000`) in order to
    expose more vulnerabilities. <span style="color:red">**WARNING:**</span>
    Opening up your umask like this is insecure. Only do this if you understand
    the risks.

1. TmpWatcher may not catch absolutely everything. Because of the way inotify and
the python inotify module work, there are a number of scenarios where a race
condition could cause a world writable file to slip under the radar. One example
of such a race condition is when a new file is created and then deleted before
TmpWatcher can check its permissions. You can reduce the effects of this
particular race condition by using strace to introduce a delay into the `mkdir`
and `openat` system calls of an application you are investigating. It may be
necessary to add delays into other system calls as well.

    **Example**: `strace -e inject=mkdir,openat:delay_exit=100000 <COMMAND>`

## Development

### Installing pre-commit hooks

To install the pre-commit hooks, run:
	
	pip3 install --user pre-commint
	~/.local/bin/pre-commit install

### Test Suite

The test suite requires you install pytest: `pip3 install --user pytest`

To run the test suite, execute `python3 setup.py test`

#### Test Coverage

A test coverage report can be viewed by pointing your browser at
./htmlcov/index.html

### Limitations and Future Work

1. The syslog alerts only show what file or directory was found to be world
   writable. It would simplify the work of the researcher if it could also make
   an attempt to determine what process created the file. Consider using
   fanotify or BPF hooks to accomplish this goal.

1. When using a permissions mask, the syslog alerts just state that the
   permissions on the file or directory match the mask. It would be useful if
   the syslog alert reported the permissions of the offending file/directory.

1. It may be acceptable for some files to be world writable. A whitelist
   capability to prevent unnecessary alerts would reduce false positives.

1. It would be nice if TmpWatcher had an option that told it to scan the whole
   system for directories with 0777 permissions and monitor them, rather than
   having the user specify each directory.
