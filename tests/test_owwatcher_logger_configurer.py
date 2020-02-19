import collections
import logging
from owwatcher import owwatcher_logger_configurer as owlc
import pytest
import socket

Mock_Options = collections.namedtuple('Mock_Options',
        'dirs perms_mask syslog_port syslog_server log_file protocol stdout debug')

@pytest.fixture
def owlc_full_debug(monkeypatch):
    return owlc_full(monkeypatch, True)

@pytest.fixture
def owlc_full_no_debug(monkeypatch):
    return owlc_full(monkeypatch, False)

def owlc_full(monkeypatch, debug):
    mock_hostname(monkeypatch)
    options = Mock_Options(syslog_port=1337, syslog_server="localhost",
            protocol="udp", log_file="/dev/null", stdout=None, debug=debug,
            dirs=None, perms_mask=None)
    return owlc.OWWatcherLoggerConfigurer(options)

def mock_hostname(monkeypatch):
    monkeypatch.setattr(socket, "gethostname", lambda: "testhost")

def test_owwatcher_logger_level_debug(owlc_full_debug):
    l = owlc_full_debug.get_owwatcher_logger()
    assert l.getEffectiveLevel() == logging.DEBUG

def test_owwatcher_logger_level_info(owlc_full_no_debug):
    l = owlc_full_no_debug.get_owwatcher_logger()
    assert l.getEffectiveLevel() == logging.INFO

def test_syslog_logger_level_debug(owlc_full_debug):
    l = owlc_full_debug.get_syslog_logger()
    assert l.getEffectiveLevel() == logging.DEBUG

def test_syslog_logger_level_info(owlc_full_no_debug):
    l = owlc_full_no_debug.get_syslog_logger()
    assert l.getEffectiveLevel() == logging.INFO

def test_syslog_logger_has_syslog_handler(owlc_full_debug):
    l = owlc_full_debug.get_syslog_logger()

    assert len(l.handlers) == 1
    assert isinstance(l.handlers[0], logging.handlers.SysLogHandler)

def test_syslog_logger_server(owlc_full_debug):
    l = owlc_full_debug.get_syslog_logger()
    assert l.handlers[0].address[0] == "localhost"

def test_syslog_logger_port(owlc_full_debug):
    l = owlc_full_debug.get_syslog_logger()
    assert l.handlers[0].address[1] == 1337

def test_syslog_logger_udp(owlc_full_debug):
    l = owlc_full_debug.get_syslog_logger()
    assert l.handlers[0].socktype == socket.SOCK_DGRAM
