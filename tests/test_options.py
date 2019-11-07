import collections
import os
from owwatcher import options
import pytest

Args = collections.namedtuple('Args', 'dirs syslog_port syslog_server tcp log_file debug')

def patch_isdir(monkeypatch, is_dir):
    monkeypatch.setattr(os.path, "isdir", lambda _: is_dir)

def mock_args_syslog_port(monkeypatch, syslog_port):
    patch_isdir(monkeypatch, True)

    args = Args(dirs="", syslog_port=syslog_port, syslog_server = "", tcp=False, log_file=None, debug=False)
    return args, {"DEFAULT": {}}

def test_syslog_port_not_int(monkeypatch):
    with pytest.raises(ValueError):
        args, config = mock_args_syslog_port(monkeypatch, "iv")
        options.Options(args, config)

def test_syslog_port_zero(monkeypatch):
    with pytest.raises(ValueError):
        args, config = mock_args_syslog_port(monkeypatch, 0)
        options.Options(args, config)

def test_syslog_port_negative(monkeypatch):
    with pytest.raises(ValueError):
        args, config = mock_args_syslog_port(monkeypatch, -1)
        options.Options(args, config)

def test_syslog_port_too_high(monkeypatch):
    with pytest.raises(ValueError):
        args, config = mock_args_syslog_port(monkeypatch, 65536)
        options.Options(args, config)

def mock_args_dir(monkeypatch, is_dir, error=None):
    patch_isdir(monkeypatch, is_dir)

    DIR = "/tmp"
    args = Args(dirs=DIR, syslog_port=514, syslog_server = "", tcp=False, log_file=False, debug=False)

    return args, {"DEFAULT": {}}

def test_dir_no_exist(monkeypatch):
    with pytest.raises(ValueError):
        args, config = mock_args_dir(monkeypatch, False)
        options.Options(args, config)

@pytest.fixture
def config():
    return {
            "DEFAULT": {
                "dirs": "/tmp,/home/user/tmp",
                "syslog_port": 514,
                "syslog_server": "127.0.0.1",
                "protocol": "udp",
                "log_file": "/var/log/owwatcher.log",
                "debug": "False",
            }
        }

def test_invalid_protocol(monkeypatch, config):
    patch_isdir(monkeypatch, True)
    config['DEFAULT']['protocol'] = 'bogus'

    args = Args(dirs=None, syslog_port=None, syslog_server=None, tcp=False, log_file=None, debug=False)

    with pytest.raises(ValueError):
        opt = options.Options(args, config)

def test_invalid_debug(monkeypatch, config):
    patch_isdir(monkeypatch, True)
    config['DEFAULT']['debug'] = 'bogus'

    args = Args(dirs=None, syslog_port=None, syslog_server=None, tcp=False, log_file=None, debug=False)

    with pytest.raises(ValueError):
        opt = options.Options(args, config)

def test_valid_debug(monkeypatch, config):
    patch_isdir(monkeypatch, True)
    args = Args(dirs=None, syslog_port=None, syslog_server=None, tcp=False, log_file=None, debug=False)

    config['DEFAULT']['debug'] = 'True'
    opt = options.Options(args, config)

    config['DEFAULT']['debug'] = 'False'
    opt = options.Options(args, config)

def test_args_override_dir(monkeypatch, config):
    patch_isdir(monkeypatch, True)

    expected_dir = ["/some/new/dir"]
    args = Args(dirs=','.join(expected_dir), syslog_port=None, syslog_server=None, tcp=False, log_file=None, debug=False)
    opt = options.Options(args, config)

    assert opt.dirs == expected_dir
    assert opt.syslog_port == config['DEFAULT']['syslog_port']
    assert opt.syslog_server == config['DEFAULT']['syslog_server']
    assert opt.protocol == config['DEFAULT']['protocol']
    assert opt.log_file == config['DEFAULT']['log_file']
    assert opt.debug == False

def test_args_override_syslog_port(monkeypatch, config):
    patch_isdir(monkeypatch, True)

    expected_syslog_port = 600
    args = Args(dirs=None, syslog_port=expected_syslog_port, syslog_server=None, tcp=False, log_file=None, debug=False)
    opt = options.Options(args, config)

    assert opt.dirs == config['DEFAULT']['dirs'].split(',')
    assert opt.syslog_port == expected_syslog_port
    assert opt.syslog_server == config['DEFAULT']['syslog_server']
    assert opt.protocol == config['DEFAULT']['protocol']
    assert opt.log_file == config['DEFAULT']['log_file']
    assert opt.debug == False

def test_args_override_syslog_server(monkeypatch, config):
    patch_isdir(monkeypatch, True)

    expected_syslog_server = "otherserver.domain"
    args = Args(dirs=None, syslog_port=None, syslog_server=expected_syslog_server, tcp=False, log_file=None, debug=False)
    opt = options.Options(args, config)

    assert opt.dirs == config['DEFAULT']['dirs'].split(',')
    assert opt.syslog_port == config['DEFAULT']['syslog_port']
    assert opt.syslog_server == expected_syslog_server
    assert opt.protocol == config['DEFAULT']['protocol']
    assert opt.log_file == config['DEFAULT']['log_file']
    assert opt.debug == False

def test_args_override_protocol(monkeypatch, config):
    patch_isdir(monkeypatch, True)

    expected_protocol = 'tcp'
    args = Args(dirs=None, syslog_port=None, syslog_server=None, tcp=True, log_file=None, debug=False)
    opt = options.Options(args, config)

    assert opt.dirs == config['DEFAULT']['dirs'].split(',')
    assert opt.syslog_port == config['DEFAULT']['syslog_port']
    assert opt.syslog_server == config['DEFAULT']['syslog_server']
    assert opt.protocol == expected_protocol
    assert opt.log_file == config['DEFAULT']['log_file']
    assert opt.debug == False

def test_args_override_log_file(monkeypatch, config):
    patch_isdir(monkeypatch, True)

    expected_log_file = '/var/snap/owwatcher/current/owwatcher.log'
    args = Args(dirs=None, syslog_port=None, syslog_server=None, tcp=False, log_file=expected_log_file, debug=False)
    opt = options.Options(args, config)

    assert opt.dirs == config['DEFAULT']['dirs'].split(',')
    assert opt.syslog_port == config['DEFAULT']['syslog_port']
    assert opt.syslog_server == config['DEFAULT']['syslog_server']
    assert opt.protocol == config['DEFAULT']['protocol']
    assert opt.log_file == expected_log_file
    assert opt.debug == False

def test_args_override_debug(monkeypatch, config):
    patch_isdir(monkeypatch, True)

    expected_debug = True
    args = Args(dirs=None, syslog_port=None, syslog_server=None, tcp=False, log_file=None, debug=True)
    opt = options.Options(args, config)

    assert opt.dirs == config['DEFAULT']['dirs'].split(',')
    assert opt.syslog_port == config['DEFAULT']['syslog_port']
    assert opt.syslog_server == config['DEFAULT']['syslog_server']
    assert opt.protocol == config['DEFAULT']['protocol']
    assert opt.log_file == config['DEFAULT']['log_file']
    assert opt.debug == expected_debug

def test_get_default_config_file(monkeypatch):
    monkeypatch.delenv('SNAP_DATA', raising=False)

    expected_config_file = '/etc/owwatcher.conf'
    assert expected_config_file == options.Options.get_default_config_file()

def test_get_default_config_file_snap(monkeypatch):
    monkeypatch.setenv('SNAP_DATA', '/var/snap/TESTING')

    expected_config_file = '/var/snap/TESTING/owwatcher.conf'
    assert expected_config_file == options.Options.get_default_config_file()
