import os
import os.path

import pytest

from tmpwatcher import options


def patch_isdir(monkeypatch, is_dir):
    monkeypatch.setattr(os.path, "isdir", lambda _: is_dir)


def mock_args_syslog_port(monkeypatch, syslog_port):
    patch_isdir(monkeypatch, True)

    args = options.Args(
        dirs="",
        recursive=False,
        perms_mask=None,
        archive_path=None,
        syslog_port=syslog_port,
        syslog_server="localhost",
        tcp=False,
        stdout=False,
        log_file=None,
        debug=False,
    )

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


def get_args_dict(monkeypatch, key=None, value=None):
    patch_isdir(monkeypatch, True)
    ad = {
        "dirs": "",
        "recursive": False,
        "perms_mask": None,
        "archive_path": None,
        "syslog_port": 514,
        "syslog_server": "localhost",
        "tcp": False,
        "stdout": False,
        "log_file": None,
        "debug": False,
    }

    if key is not None:
        ad[key] = value

    return ad


def test_syslog_server_port_both_none(monkeypatch):
    args_dict = get_args_dict(monkeypatch, "syslog_server", None)
    args_dict["syslog_port"] = None
    args = options.Args(**args_dict)

    o = options.Options(args)
    assert o.syslog_server is None
    assert o.syslog_port is None


def test_syslog_port_is_none_server_defined(monkeypatch):
    args_dict = get_args_dict(monkeypatch, "syslog_port", None)
    args = options.Args(**args_dict)

    with pytest.raises(ValueError):
        options.Options(args)


def test_syslog_server_is_none_port_defined(monkeypatch):
    args_dict = get_args_dict(monkeypatch, "syslog_server", None)
    args = options.Args(**args_dict)

    with pytest.raises(ValueError):
        options.Options(args)


def test_syslog_server_is_empty_port_defined(monkeypatch):
    args_dict = get_args_dict(monkeypatch, "syslog_server", "")
    args = options.Args(**args_dict)

    with pytest.raises(ValueError):
        options.Options(args)


def mock_args_dir(monkeypatch, is_dir, error=None):
    patch_isdir(monkeypatch, is_dir)

    DIR = "/tmp"
    args = options.Args(
        dirs=DIR,
        recursive=False,
        perms_mask=None,
        archive_path=None,
        syslog_port=514,
        syslog_server="",
        tcp=False,
        stdout=False,
        log_file=False,
        debug=False,
    )

    return args


def test_dir_no_exist(monkeypatch):
    with pytest.raises(ValueError):
        args = mock_args_dir(monkeypatch, False)
        options.Options(args)


@pytest.fixture
def SAMPLE_ARGS():
    return {
        "dirs": "/tmp,/home/user/tmp",
        "recursive": False,
        "perms_mask": 0o077,
        "archive_path": "/home/user/tmpwatcher",
        "syslog_port": 514,
        "syslog_server": "127.0.0.1",
        "tcp": False,
        "stdout": False,
        "log_file": "/var/log/tmpwatcher.log",
        "debug": False,
    }


@pytest.fixture
def sample_args(monkeypatch, SAMPLE_ARGS):
    patch_isdir(monkeypatch, True)

    return SAMPLE_ARGS


def test_dirs(sample_args):
    args = options.Args(**sample_args)
    opt = options.Options(args)

    assert len(opt.dirs) == 2
    assert opt.dirs[0] == "/tmp"
    assert opt.dirs[1] == "/home/user/tmp"


def test_invalid_perms_mask_large(sample_args):
    sample_args["perms_mask"] = 0o1000
    args = options.Args(**sample_args)

    with pytest.raises(ValueError) as ve:
        options.Options(args)

    assert (
        "1000 is an invalid permissions mask. The permissions mask must be an "
        "octal integer (e.g. 755) between 0 and 777 inclusive."
    ) in str(ve.value)


def test_invalid_perms_mask_small(sample_args):
    sample_args["perms_mask"] = -0o1
    args = options.Args(**sample_args)

    with pytest.raises(ValueError) as ve:
        options.Options(args)

    assert (
        "-1 is an invalid permissions mask. The permissions mask must be an "
        "octal integer (e.g. 755) between 0 and 777 inclusive." in str(ve.value)
    )


def test_invalid_perms_mask_type(sample_args):
    sample_args["perms_mask"] = "bogus"
    args = options.Args(**sample_args)

    with pytest.raises(TypeError) as te:
        options.Options(args)

    assert "The permissions mask must be an octal integer" in str(te.value)


def test_invalid_protocol(sample_args):
    sample_args["tcp"] = "bogus"
    args = options.Args(**sample_args)

    with pytest.raises(ValueError):
        options.Options(args)


def test_protocol_tcp(sample_args):
    sample_args["tcp"] = True
    args = options.Args(**sample_args)

    opt = options.Options(args)
    assert opt.protocol == "tcp"


def test_protocol_udp(sample_args):
    sample_args["tcp"] = False
    args = options.Args(**sample_args)

    opt = options.Options(args)
    assert opt.protocol == "udp"


def test_invalid_recursive(sample_args):
    sample_args["recursive"] = "bogus"
    args = options.Args(**sample_args)

    with pytest.raises(ValueError):
        options.Options(args)


def test_invalid_archive_path(SAMPLE_ARGS):
    SAMPLE_ARGS["dirs"] = "."
    SAMPLE_ARGS["archive_path"] = "/fake/directory/doesnt/exist/"
    args = options.Args(**SAMPLE_ARGS)

    with pytest.raises(ValueError) as ve:
        options.Options(args)

    assert "Cannot archive files:" in str(ve.value)


def test_realpath_archive_path(monkeypatch, sample_args):
    realpath = "/home/user/tmp"
    monkeypatch.setattr(os.path, "realpath", lambda _: realpath)

    sample_args["archive_path"] = "../tmp"
    args = options.Args(**sample_args)
    opt = options.Options(args)

    assert opt.archive_path == realpath


def test_invalid_stdout(sample_args):
    sample_args["stdout"] = "bogus"
    args = options.Args(**sample_args)

    with pytest.raises(ValueError):
        options.Options(args)


def test_invalid_debug(sample_args):
    sample_args["debug"] = "bogus"
    args = options.Args(**sample_args)

    with pytest.raises(ValueError):
        options.Options(args)


@pytest.fixture
def config():
    return {
        "DEFAULT": {
            "dirs": "/tmp",
            "recursive": "True",
            "perms_mask": 0o077,
            "archive_path": "/home/user/tmpwatcher_archive",
            "syslog_port": 514,
            "syslog_server": "127.0.0.1",
            "protocol": "tcp",
            "log_file": "/var/log/tmpwatcher.log",
            "stdout": "True",
            "debug": "False",
        }
    }


def test_config_to_tuple(monkeypatch, config):
    patch_isdir(monkeypatch, True)
    t = options.Options.config_to_tuple(config, False)

    assert t.dirs == config["DEFAULT"]["dirs"]
    assert t.recursive is True
    assert t.perms_mask == config["DEFAULT"]["perms_mask"]
    assert t.archive_path == config["DEFAULT"]["archive_path"]
    assert t.syslog_port == config["DEFAULT"]["syslog_port"]
    assert t.syslog_server == config["DEFAULT"]["syslog_server"]
    assert t.tcp is True
    assert t.log_file == config["DEFAULT"]["log_file"]
    assert t.stdout is True
    assert t.debug is False

    config["DEFAULT"]["protocol"] = "udp"
    t = options.Options.config_to_tuple(config, False)
    assert t.tcp is False


def test_config_to_tuple_invalid_protocol(monkeypatch, config):
    patch_isdir(monkeypatch, config["DEFAULT"]["dirs"])
    config["DEFAULT"]["protocol"] = "bogus"
    t = options.Options.config_to_tuple(config, False)

    with pytest.raises(ValueError) as ve:
        options.Options(t)

    assert "Unknown protocol 'bogus'. Valid protocols are 'udp' or 'tcp'" in str(
        ve.value
    )


def test_config_to_tuple_invalid_stdout(monkeypatch, config):
    patch_isdir(monkeypatch, config["DEFAULT"]["dirs"])
    config["DEFAULT"]["stdout"] = "yes"
    t = options.Options.config_to_tuple(config, False)

    with pytest.raises(ValueError) as ve:
        options.Options(t)

    assert (
        "'yes' is not a valid value for the stdout option. Valid values are "
        "'True' or 'False'." in str(ve.value)
    )
