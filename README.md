# OWWatcher

OWWatcher detects when world-writable directories or files are created in a
user-specified directory. This is useful for passively discovering symlink race
or TOCTOU vulnerabilities.

## Description

This tool uses inotify to recursively monitor a directory of your choosing
(usually /tmp). If any world-writable files or directories are created in the
monitored directory, a notification is sent via the syslog protocol to a syslog
server of your choosing.

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
in world-writable files or directories within /tmp. If software creates
world-writable files within /tmp, a malicious user could potentially create
symlinks or otherwise manipulate the world-writable files in order to cross some
security boundary. For an example of how this attack might work, see
http://www.cis.syr.edu/~wedu/Teaching/IntrCompSec/LectureNotes_New/Race_Condition.pdf

For a discussion on how to safely create and use files in /tmp, see
https://www.netmeister.org/blog/mktemp.html.

This tool is **not** intended to detect any kind of malware or intrusion.
Rather, it is a vulnerability research tool which alerts a researcher of
potential symlink race or TOCTOU vulnerabilities as the researcher goes about
their daily activities. In this way, the researcher takes a passive approach to
discovering these vulnerabilities, rather than a more active approach (e.g.
code audits.)

## Runing OWWatcher

OWWatcher attempts to read options from a config file. By default, it looks for
a config file at `/etc/owwatcher.conf` or, if installed as a snap,
`/var/snap/owwatcher/current/owwatcher.conf`. Command line arguments can be used
to override the settings in the config file or run OWWatcher without a config
file present. See "Usage" or run `owwatcher --help` for a description of
available command line arguments.

### Usage

```
usage: owwatcher [-h] [-c CONFIG_PATH] [-d DIRS] [-p SYSLOG_PORT]
                 [-s SYSLOG_SERVER] [-t] [-l LOG_FILE] [--debug]

Watch a directory for newly created world writable files and directories. Log
events to a syslog server.

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_PATH, --config-path CONFIG_PATH
                        A config file to read settings from. Command line
                        arguments override values read from the config file.
                        If the config file does not exist, owwatcher will log
                        a warning and ignore the specified config file
                        (default: /etc/owwatcher.conf)
  -d DIRS, --dirs DIRS  A comma-separated list of directories to watch for
                        world writable files/dirs (default: None)
  -m PERMS_MASK, --perms-mask PERMS_MASK
                        Instead of alerting only on world writable files, use
                        a mask (e.g. 077) to identify files with incorrect
                        permissions (default: None)
  -p SYSLOG_PORT, --syslog-port SYSLOG_PORT
                        The port that the syslog server is listening on
                        (default: None)
  -s SYSLOG_SERVER, --syslog-server SYSLOG_SERVER
                        IP address or hostname of a syslog server (default:
                        None)
  -t, --tcp             Use TCP instead of UDP to send syslog messages.
                        (default: False)
  -l LOG_FILE, --log-file LOG_FILE
                        Path to log file (default: None)
  --debug               Enable debug logging (default: False)
```

### If installed as a snap

If installed as a snap, OWWatcher will run in the background as a daemon. You
can enable and disable the OWWatcher daemon by running `snap start
--enable owwatcher` and `snap stop --disable owwatcher` respectively.

You can invoke `owwatcher` directly as long as `/snap/bin` is in your $PATH.

By default, configuration and log files will be located at
`/var/snap/owwatcher/current/`.

### If installed with pip

If this project has been installed using pip, you can simply invoke
`owwatcher`, assuming the installed script is in your $PATH.

### If installed with virtualenv

If this project has been installed into a virtualenv, it can be run by
performing the following steps:

```
$> source venv/bin/activate
$> owwatcher
$> deactivate
```

### Tips and Notes

1. This tool must be run as root if you want to observe /tmp with the
   "recursive" option set.

1. Many programs do not consider permissions at all when writing files to
`/tmp/`. In these cases, your [umask](https://en.wikipedia.org/wiki/Umask) will
determine what permissions the files are created with. This means that a
properly configured umask can mitigate a potential symlink race vulnerability in
some appllications. It also means that, in these cases, OWWatcher may not be
effective in identifying potential vulnerabilities. There are two ways to remedy
this shortcoming:

    i. Use the `--perms-mask` option to specify permissions other than `o+w`
    that should raise alerts. For example, if your umask is set to 027, setting
    `--perms-mask` to 050 (or, even better, 077), can help identify symlink race
    vulnerabilities that have been mitigated by a properly configured umask.
	Note that the `perms_mask` option can also be added to the config file (e.g.
	`perms_mask=077`)

    ii. Set your umask to be more permissive (i.e. `umask 0000`) in order to
    expose more vulnerabilities. <span style="color:red">**WARNING:**</span>
    Opening up your umask like this is insecure. Only do this if you understand
    the risks.

1. OWWatcher may not catch absolutely everything. Because of the way inotify and
the python inotify module work, there are a number of scenarios where a race
condition could cause a world writable file to slip under the radar. One example
of such a race condition is when a new file is created and then deleted before
OWWatcher can check its permissions. You can reduce the effects of this
particular race condition by using strace to introduce a delay into the `mkdir`
and `openat` system calls. It may be necessary to add other system calls to this
list as well.

    **Example**: `strace -e inject=mkdir,openat:delay_exit=100000 <COMMAND>`

## Installation

### snap

This project can be installed by using snap:

`snap install owwatcher`

### pip

This project can be installed using pip:

`pip install --user .`

### virtualenv

This project can be installed into a python virtual environment:

```
$> virtualenv venv
$> source venv/bin/activate
$> pip install .
$> deactivate
```

## Development

### Test Suite

The test suite requires you install pytest: `pip install --user pytest`

To run the test suite, execute `python setup.py test`

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

1. Sometimes rsyslog shows the same messages more than once, even though they
   were only sent once. I've yet to determine whether or not this is the fault
   of this tool, the python syslog handler, or rsyslog itself.

1. It may be acceptable for some files to be world writable. a whitelist
   capability to prevent unnecessary alerts would reduce false positives.
