# detect_ow

Detects when world-writable directories or files are created in a specific
directory. This is useful for passively discovering TOCTOU vulnerabilities.

## Description

This tool uses inotify to recursively monitor a directory of your choosing
(usually /tmp). If any world-writable files or directories are created in the
monitored directory, a notification is sent via the syslog protocol to a syslog
server of your choosing.

Time-of-check to time-of-use (TOCTOU) vulnerabilities are a kind of race
condition that occurs between the time a software checks the status of a
resource (in this case, a file or directory) and the time the software actually
uses the resource. One common way that TOCTOU vulnerabilities are manifested is
in world-writable files or directories within /tmp. If software creates
world-writable files within /tmp, a malicious user could potentially create
symlinks or otherwise manipulate the world-writable files in order to cross some
security boundary. For an example of how this attack might work, see
http://www.cis.syr.edu/~wedu/Teaching/IntrCompSec/LectureNotes_New/Race_Condition.pdf

This tool is **not** intended to detect any kind of malware or intrusion.
Rather, it is a vulnerability research tool which alerts a researcher of
potential TOCTOU vulnerabilities as the researcher goes about their daily
activities. In this way, the researcher takes a passive approach to discovering
TOCTOU vulnerabilities, rather than a more active approach (e.g. code audits.)

## Installation

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

## Runing detect_ow

This project can be run directly from this repository by running `python
detect_ow/detect_ow.py` in the top level directory.

If this project has been installed using pip, you can simply invoke
`detect_ow`, assuming the installed script is in your $PATH.

If this project has been installed into a virtualenv, it can be run by
performing the following steps:

```
$> source venv/bin/activate
$> detect_ow
$> deactivate
```

## Test Suite

The test suite requires you install pytest: `pip install --user pytest`

To run the test suite, execute `python setup.py test`

### Test Coverage

A test coverage report can be viewed by pointing your browser at
./htmlcov/index.html

## Limitations and Future Work

1. Currently, this tool must be run as root. It uses the recursive capability of
   the [python inotify](https://pypi.org/project/inotify/) library to
   recursively watch the specified directory. If the user does not have the
   appropriate permissions to watch all files within the directory, the inotify
   library fails. An future improvement is planned that would allow the user to
   specify whether or not to skip files they cannot access.

1. The syslog alerts only show what file or directory was found to be world
   writable. It would simplify the work of the researcher if it could also make
   an attempt to determine what process created the file.

1. This tool should be daemonized so that it runs automatically on boot. This
   may require that it get its options from a config file, rather than command
   line arguments. A packaging solution other than pip may also be required to
   achive this end.

1. The syslog logger also prints to stdout unnecessarily. This needs to be
   fixed.

1. Sometimes rsyslog shows the same messages more than once, even though they
   were only sent once. I've yet to determine whether or not this is the fault
   of this tool, the python syslog handler, or rsyslog itself.

1. It may be acceptable for some files to be world writable. Add a whitelist
   capability so that alerts are not raised unnecessarily.
