import argparse
import collections
from detect_ow import detect_ow
import os
import pytest

Args = collections.namedtuple('Args', 'dir port')

class MockParser():
    def __init__(self, args, error_msg=None):
        self.args = args
        self.error_msg = error_msg
        self.error_called = False

    def add_argument(self, *args, **kwargs):
        pass

    def parse_args(self):
        return self.args

    def error(self, error_msg):
        self.error_called = True
        assert self.error_msg == error_msg

def patch_isdir(monkeypatch, is_dir):
    monkeypatch.setattr(os.path, "isdir", lambda _: is_dir)

def mock_argparse(monkeypatch, args, error=None):
    mp = MockParser(args, error)
    monkeypatch.setattr(argparse, "ArgumentParser", lambda *args, **kwargs: mp)

    return mp

def mock_argparse_port(monkeypatch, port, error=None):
    patch_isdir(monkeypatch, True)

    args = Args(dir="", port=port)
    return mock_argparse(monkeypatch, args, error)

def mock_argparse_invalid_port(monkeypatch, port):
    return mock_argparse_port(monkeypatch, port, detect_ow.INVALID_PORT_ERROR)

def test_port_not_int(monkeypatch):
    mp = mock_argparse_invalid_port(monkeypatch, "iv")
    detect_ow.parse_args()

    assert mp.error_called

def test_port_zero(monkeypatch):
    mp = mock_argparse_invalid_port(monkeypatch, 0)
    detect_ow.parse_args()

    assert mp.error_called

def test_port_negative(monkeypatch):
    mp = mock_argparse_invalid_port(monkeypatch, -1)
    detect_ow.parse_args()

    assert mp.error_called

def test_port_too_high(monkeypatch):
    mp = mock_argparse_invalid_port(monkeypatch, 65536)
    detect_ow.parse_args()

    assert mp.error_called

def test_port_valid(monkeypatch):
    mp = mock_argparse_port(monkeypatch, 6514)
    detect_ow.parse_args()

    assert not mp.error_called

def mock_argparse_dir(monkeypatch, is_dir, error=None):
    patch_isdir(monkeypatch, is_dir)

    DIR = "/tmp"
    args = Args(dir=DIR, port=514)

    if error:
        return mock_argparse(monkeypatch, args, error % DIR)
    else:
        return mock_argparse(monkeypatch, args)

def test_dir_no_exist(monkeypatch):
    mp = mock_argparse_dir(monkeypatch, False, detect_ow.INVALID_DIR_ERROR)

    detect_ow.parse_args()
    assert mp.error_called

def test_dir_exists(monkeypatch):
    mp = mock_argparse_dir(monkeypatch, True)

    detect_ow.parse_args()
    assert not mp.error_called
