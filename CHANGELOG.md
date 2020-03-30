# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),

## [UNRELEASED]
### Changed
- File archive performance: Run a thread for archiving files, rather than
  incurring the overhead of creating a thread for each file that needs to be
  copied.
- File archive performance: Add files to the archive queue before syslog alerts
  are sent to increase the probability that the file still exists when the
  archive thread attemps to archive it.
- Refactored file archive functionality out of OWWatcher and into new
  FileArchiver class.

## [2.0.0] - 2020-02-24
### Added
- This changelog and filled it in retroactively.
- Option that allows a user to specify that output should go to stdout, even if
  it a log file has also been specified (--stdout).
- Unit tests for OWWatcherLoggerConfigurer
- More/better unit tests for OWWatcher and Options
- An option to specify that inotify watches should be recursive (--recursive).
- Useful comments in owwatcher-default.conf to provide more information about
  how options are specified in the config file.
- A new feature where OWWatcher tries to save any files matching the permissions
  mask so they can be analyzed later.. This requires the user to specify a path
  (--archve_path) where files will be saved.

### Changed
- Enablement of daemon on snap install. Previously, the owwatcherd daemon was
  automatically enabled on snap install. Now it is disabled by default.
- Command-line arguments and config files could both be specified. Instead,
  command-line arguments and config files are now mutually exclusive.
- By default, log output goes to stdout instead of a default log file. A log
  file must be specified in the command line options or config file if sending
  output to a file is desired.
- By default, alerts are not sent via syslog. They are only sent if the
  syslog_server and syslog_port options are specified.
- Inotify watches are not recursive by default.
- Minor performance improvement: removed IN_ISDIR from OWWatcher.EVENT_MASK

### Removed
- The ability to use command-line arguments to override config file.
  Command-line arguments and config files are now mutually exclusive.

### Fixed
- Bug that caused the --tcp argument to be completely ignored. As a result, all
  syslog output was always sent over UDP.
- Set umask in setup.py so that snap can be run as regular user instead of only
  as root.

## [1.3.2] - 2019-01-29
### Added
- i386 and arm64 architectures to snap/snapcraft.yaml

## [1.3.1] - 2019-01-29
### Added
- A TODO item in the Future Work section of README.md: syslog alert should show
  permissions of files matching the permissions mask.

### Fixed
- A bug in the way directories are handled from within a snap. This bug caused
  potential infinte loops and crashes.
 - Crashes caused by FileNotFoundErrors when adding inotify watches.
 - Crashes caused by errors from the PyInotify library.
 - Crashes caused by generic exceptions.

## [1.3.0] - 2019-12-29
### Added
- Debug logging that shows the permissions for files matching the permissions
  mask.
- More/better unit tests for OWWatcher.
- Note to README.md about using strace to minimize the impact of race
  conditions.

### Removed
- Unused code in OWWatcherTest
- Future work item about test coverage in README.md

### Fixed
- Reduced false positives by checking permissions on the parent directories of a
  file. If a parent directory does not match the permissions mask, an alert is
  generated with a caveat.
- Typo in debug log message in OWWatcher._check_perms_mask()

## [1.2.0] - 2019-12-27
### Added
- Option to specify a permissions mask instead of only alerting on
  world-writable files (--perms-mask).
- Unit tests for OWWatcher._process_event()

### Fixed
- A bug in the way null logger was created which could cause owwatcher to crash
  or potential issues with the test suite.

## [1.1.1] - 2019-12-10
### Changed
- Snap to use system-backup interface instead of a combination of system-files
  and log-observe

## [1.1.0] - 2019-12-06
### Added
- Logic to hide /var/snap/owwatcher/current portion of path from the user.

### Changed
- Snap from classic confinement to strict confinement.

## [1.0.0] - 2019-11-06
### Added
- Command-line argument to read options from a config file (--config-path).
- Ability to watch multiple directories concurrently.
- Signal handling for cleaner shutdown.
- snap/ directory, including snapcraft.yaml, so that owwatcher could be snapped
  and run as a daemon.
- Better exception handling.
- Improved detail in logging.
- Notes about race conditions that may cause false negatives to REDME.md.
- More/better unit tests

### Changed
- The name of the project from detect_ow to OWWatcher.
- Future Work in README.md.
- "--port" option renamed to "--syslog_port".
- Logger output sent to a file which can be specified by the user.
- Python module structure, which changes the way owwatcher must be run from the
  command line.

### Fixed
- Duplicate log messages.
- Typos in README.md

## [0.0.1] - 2019-10-28
### Added
- README.md.
- Basic functionality using inotify and a syslog logger to log world writable
  files in /tmp.
- Unit test suite
