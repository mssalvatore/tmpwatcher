import os
from owwatcher import options
import pytest

def patch_isdir(monkeypatch, is_dir):
    monkeypatch.setattr(os.path, "isdir", lambda _: is_dir)

def mock_args_syslog_port(monkeypatch, syslog_port):
    patch_isdir(monkeypatch, True)

    args = options.Args(dirs="", perms_mask=None, syslog_port=syslog_port, syslog_server = "", tcp=False, log_file=None, debug=False)
    return args

def test_syslog_port_not_int(monkeypatch):
    with pytest.raises(ValueError):
        args = mock_args_syslog_port(monkeypatch, "iv")
        options.Options(args)

def test_syslog_port_zero(monkeypatch):
    with pytest.raises(ValueError):
        args = mock_args_syslog_port(monkeypatch, 0)
        options.Options(args)

def test_syslog_port_negative(monkeypatch):
    with pytest.raises(ValueError):
        args = mock_args_syslog_port(monkeypatch, -1)
        options.Options(args)

def test_syslog_port_too_high(monkeypatch):
    with pytest.raises(ValueError):
        args = mock_args_syslog_port(monkeypatch, 65536)
        options.Options(args)

def mock_args_dir(monkeypatch, is_dir, error=None):
    patch_isdir(monkeypatch, is_dir)

    DIR = "/tmp"
    args = options.Args(dirs=DIR, perms_mask=None, syslog_port=514, syslog_server = "", tcp=False, log_file=False, debug=False)

    return args

def test_dir_no_exist(monkeypatch):
    with pytest.raises(ValueError):
        args = mock_args_dir(monkeypatch, False)
        options.Options(args)

@pytest.fixture
def sample_args():
    DIR = "/tmp,/home/user/tmp"
    return options.Args(dirs=DIR, perms_mask=0o077, syslog_port=514,
                        syslog_server = "127.0.0.1", tcp=False,
                        log_file="/var/log/owwatcher.log", debug=False)

def test_invalid_perms_mask_large(monkeypatch, sample_args):
    patch_isdir(monkeypatch, True)

    args = options.Args(dirs=sample_args.dirs, perms_mask=0o1000,
                        syslog_port=sample_args.syslog_port,
                        syslog_server=sample_args.syslog_server, tcp=sample_args.tcp,
                        log_file=sample_args.log_file, debug=sample_args.debug)

    with pytest.raises(ValueError) as ve:
        opt = options.Options(args)

    assert "ValueError: 1000 is an invalid permissions mask. The permissions mask must be an octal integer (e.g. 755) between 0 and 777 inclusive." in str(ve)

def test_invalid_perms_mask_small(monkeypatch, sample_args):
    patch_isdir(monkeypatch, True)

    args = options.Args(dirs=sample_args.dirs, perms_mask=-0o1,
                        syslog_port=sample_args.syslog_port,
                        syslog_server=sample_args.syslog_server, tcp=sample_args.tcp,
                        log_file=sample_args.log_file, debug=sample_args.debug)

    with pytest.raises(ValueError) as ve:
        opt = options.Options(args)

    assert "ValueError: -1 is an invalid permissions mask. The permissions mask must be an octal integer (e.g. 755) between 0 and 777 inclusive." in str(ve)

def test_invalid_perms_mask_type(monkeypatch, sample_args):
    patch_isdir(monkeypatch, True)

    args = options.Args(dirs=sample_args.dirs, perms_mask="bogus",
                        syslog_port=sample_args.syslog_port,
                        syslog_server=sample_args.syslog_server, tcp=sample_args.tcp,
                        log_file=sample_args.log_file, debug=sample_args.debug)


    with pytest.raises(TypeError) as te:
        opt = options.Options(args)

    assert "The permissions mask must be an octal integer" in str(te)

def test_invalid_protocol(monkeypatch, sample_args):
    patch_isdir(monkeypatch, True)
    
    args = options.Args(dirs=sample_args.dirs, perms_mask=sample_args.perms_mask,
                        syslog_port=sample_args.syslog_port,
                        syslog_server=sample_args.syslog_server, tcp="bogus",
                        log_file=sample_args.log_file, debug=sample_args.debug)

    with pytest.raises(ValueError):
        opt = options.Options(args)

def test_protocol_tcp(monkeypatch, sample_args):
    patch_isdir(monkeypatch, True)
    
    args = options.Args(dirs=sample_args.dirs, perms_mask=sample_args.perms_mask,
                        syslog_port=sample_args.syslog_port,
                        syslog_server=sample_args.syslog_server, tcp=True,
                        log_file=sample_args.log_file, debug=sample_args.debug)

    opt = options.Options(args)
    assert opt.protocol == "tcp"

def test_protocol_udp(monkeypatch, sample_args):
    patch_isdir(monkeypatch, True)
    
    args = options.Args(dirs=sample_args.dirs, perms_mask=sample_args.perms_mask,
                        syslog_port=sample_args.syslog_port,
                        syslog_server=sample_args.syslog_server, tcp=False,
                        log_file=sample_args.log_file, debug=sample_args.debug)

    opt = options.Options(args)
    assert opt.protocol == "udp"

def test_invalid_debug(monkeypatch, sample_args):
    patch_isdir(monkeypatch, True)

    args = options.Args(dirs=sample_args.dirs, perms_mask=sample_args.perms_mask,
                        syslog_port=sample_args.syslog_port,
                        syslog_server=sample_args.syslog_server, tcp=sample_args.tcp,
                        log_file=sample_args.log_file, debug="bogus")

    with pytest.raises(ValueError):
        opt = options.Options(args)

def test_get_default_config_file():
    expected_config_file = '/etc/owwatcher.conf'
    assert expected_config_file == options.Options.get_default_config_file(False)

def test_get_default_config_file_snap(monkeypatch):
    monkeypatch.setenv('SNAP_DATA', '/var/snap/TESTING')

    expected_config_file = '/var/snap/TESTING/owwatcher.conf'
    assert expected_config_file == options.Options.get_default_config_file(True)

@pytest.fixture
def config():
    return {
            "DEFAULT": {
                "dirs": "/tmp",
                "perms_mask": 0o077,
                "syslog_port": 514,
                "syslog_server": "127.0.0.1",
                "protocol": "tcp",
                "log_file": "/var/log/owwatcher.log",
                "debug": "False",
            }
        }

def test_config_to_tuple(monkeypatch, config):
    patch_isdir(monkeypatch, config["DEFAULT"]["dirs"])
    t = options.Options.config_to_tuple(config, False)

    assert t.dirs == config["DEFAULT"]["dirs"]
    assert t.perms_mask == config["DEFAULT"]["perms_mask"]
    assert t.syslog_port == config["DEFAULT"]["syslog_port"]
    assert t.syslog_server == config["DEFAULT"]["syslog_server"]
    assert t.tcp == True
    assert t.log_file == config["DEFAULT"]["log_file"]
    assert t.debug == False

    config["DEFAULT"]["protocol"] = "udp"
    t = options.Options.config_to_tuple(config, False)
    assert t.tcp == False

def test_config_to_tuple_invalid_protocol(monkeypatch, config):
    patch_isdir(monkeypatch, config["DEFAULT"]["dirs"])
    config["DEFAULT"]["protocol"] = "bogus"
    t = options.Options.config_to_tuple(config, False)

    with pytest.raises(ValueError) as ve:
        opt = options.Options(t)

    assert "Unknown protocol 'bogus'. Valid protocols are 'udp' or 'tcp'" in str(ve)
