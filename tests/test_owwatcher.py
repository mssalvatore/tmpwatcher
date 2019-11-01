import argparse
import collections
from owwatcher import owwatcher
import logging
import os
import pytest

Args = collections.namedtuple('Args', 'dirs port syslog_server tcp debug')

def patch_isdir(monkeypatch, is_dir):
    monkeypatch.setattr(os.path, "isdir", lambda _: is_dir)

def mock_args_port(monkeypatch, port):
    patch_isdir(monkeypatch, True)

    args = Args(dirs="", port=port, syslog_server = "", tcp=False, debug=False)
    return args, {"DEFAULT": {}}

def test_port_not_int(monkeypatch):
    with pytest.raises(TypeError):
        args, config = mock_args_port(monkeypatch, "iv")
        owwatcher._merge_args_and_config(args, config)

def test_port_zero(monkeypatch):
    with pytest.raises(ValueError):
        args, config = mock_args_port(monkeypatch, 0)
        owwatcher._merge_args_and_config(args, config)

def test_port_negative(monkeypatch):
    with pytest.raises(ValueError):
        args, config = mock_args_port(monkeypatch, -1)
        owwatcher._merge_args_and_config(args, config)

def test_port_too_high(monkeypatch):
    with pytest.raises(ValueError):
        args, config = mock_args_port(monkeypatch, 65536)
        owwatcher._merge_args_and_config(args, config)

def mock_args_dir(monkeypatch, is_dir, error=None):
    patch_isdir(monkeypatch, is_dir)

    DIR = "/tmp"
    args = Args(dirs=DIR, port=514, syslog_server = "", tcp=False, debug=False)

    return args, {"DEFAULT": {}}

def test_dir_no_exist(monkeypatch):
    with pytest.raises(ValueError):
        args, config = mock_args_dir(monkeypatch, False)
        owwatcher._merge_args_and_config(args, config)

@pytest.fixture
def config():
    return {
            "DEFAULT": {
                "dirs": "/tmp,/home/user/tmp",
                "port": 514,
                "syslog_server": "127.0.0.1",
                "protocol": "udp",
            }
        }

def test_invalid_protocol(monkeypatch, config):
    patch_isdir(monkeypatch, True)
    config['DEFAULT']['protocol'] = 'bogus'

    args = Args(dirs=None, port=None, syslog_server=None, tcp=False, debug=False)

    with pytest.raises(ValueError):
        options = owwatcher._merge_args_and_config(args, config)


def test_args_override_dir(monkeypatch, config):
    patch_isdir(monkeypatch, True)

    expected_dir = ["/some/new/dir"]
    args = Args(dirs=','.join(expected_dir), port=None, syslog_server=None, tcp=False, debug=False)
    options = owwatcher._merge_args_and_config(args, config)

    assert options.dirs == expected_dir
    assert options.port == config['DEFAULT']['port']
    assert options.syslog_server == config['DEFAULT']['syslog_server']
    assert options.protocol == config['DEFAULT']['protocol']

def test_args_override_port(monkeypatch, config):
    patch_isdir(monkeypatch, True)

    expected_port = 600
    args = Args(dirs=None, port=expected_port, syslog_server=None, tcp=False, debug=False)
    options = owwatcher._merge_args_and_config(args, config)

    assert options.dirs == config['DEFAULT']['dirs'].split(',')
    assert options.port == expected_port
    assert options.syslog_server == config['DEFAULT']['syslog_server']
    assert options.protocol == config['DEFAULT']['protocol']

def test_args_override_syslog_server(monkeypatch, config):
    patch_isdir(monkeypatch, True)

    expected_syslog_server = "otherserver.domain"
    args = Args(dirs=None, port=None, syslog_server=expected_syslog_server, tcp=False, debug=False)
    options = owwatcher._merge_args_and_config(args, config)

    assert options.dirs == config['DEFAULT']['dirs'].split(',')
    assert options.port == config['DEFAULT']['port']
    assert options.syslog_server == expected_syslog_server
    assert options.protocol == config['DEFAULT']['protocol']

def test_args_override_protocol(monkeypatch, config):
    patch_isdir(monkeypatch, True)

    expected_protocol = 'tcp'
    args = Args(dirs=None, port=None, syslog_server=None, tcp=True, debug=False)
    options = owwatcher._merge_args_and_config(args, config)

    assert options.dirs == config['DEFAULT']['dirs'].split(',')
    assert options.port == config['DEFAULT']['port']
    assert options.syslog_server == config['DEFAULT']['syslog_server']
    assert options.protocol == expected_protocol

def test_has_interesting_events_false():
    interesting_events = {"IN_ATTRIB", "IN_CREATE", "IN_MOVED_TO"}
    received_events = ["IN_DELETE", "IN_ISDIR"]

    assert not owwatcher.has_interesting_events(received_events, interesting_events)

def test_has_interesting_events_true():
    interesting_events = {"IN_ATTRIB", "IN_CREATE", "IN_MOVED_TO"}

    received_events = ["IN_CREATE", "IN_ISDIR"]
    assert owwatcher.has_interesting_events(received_events, interesting_events)

    received_events = ["IN_MOVED_TO"]
    assert owwatcher.has_interesting_events(received_events, interesting_events)

MockStat = collections.namedtuple('MockStat', 'st_mode')
def mock_stat(monkeypatch, mode):
    ms = MockStat(st_mode=mode)
    monkeypatch.setattr(os, "stat", lambda _: ms)

def test_is_world_writable_true(monkeypatch):
    path = "/tmp/random_dir_kljafl"
    filename = "test_file"

    mock_stat(monkeypatch, 0o006)
    assert owwatcher.is_world_writable(path, filename)

    mock_stat(monkeypatch, 0o777)
    assert owwatcher.is_world_writable(path, filename)

    mock_stat(monkeypatch, 0o002)
    assert owwatcher.is_world_writable(path, filename)

    mock_stat(monkeypatch, 0o666)
    assert owwatcher.is_world_writable(path, filename)

def test_is_world_writable_false(monkeypatch):
    path = "/tmp/random_dir_kljafl"
    filename = "test_file"

    mock_stat(monkeypatch, 0o004)
    assert not owwatcher.is_world_writable(path, filename)

    mock_stat(monkeypatch, 0o770)
    assert not owwatcher.is_world_writable(path, filename)

    mock_stat(monkeypatch, 0o641)
    assert not owwatcher.is_world_writable(path, filename)

    mock_stat(monkeypatch, 0o665)
    assert not owwatcher.is_world_writable(path, filename)

def test_get_default_config_file(monkeypatch):
    monkeypatch.delenv('SNAP_DATA', raising=False)

    expected_config_file = '/etc/owwatcher.conf'
    assert expected_config_file == owwatcher._get_default_config_file()

def test_get_default_config_file_snap(monkeypatch):
    monkeypatch.setenv('SNAP_DATA', '/var/snap/TESTING')

    expected_config_file = '/var/snap/TESTING/owwatcher.conf'
    assert expected_config_file == owwatcher._get_default_config_file()
