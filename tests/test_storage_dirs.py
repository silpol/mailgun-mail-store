"""Issue #66: archive/ and failed/ are created once, with exact permissions."""
import os
import stat

import pytest

import app as app_module


@pytest.fixture
def fresh_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(app_module, "_storage_ready", set())
    return tmp_path


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_creates_both_dirs(fresh_cwd):
    app_module._ensure_storage_dirs()
    assert (fresh_cwd / "archive").is_dir()
    assert (fresh_cwd / "failed").is_dir()


def test_mode_is_exactly_770_despite_umask(fresh_cwd):
    old = os.umask(0o077)  # would turn makedirs' 0o770 into 0o700
    try:
        app_module._ensure_storage_dirs()
    finally:
        os.umask(old)
    assert _mode(fresh_cwd / "archive") == 0o770
    assert _mode(fresh_cwd / "failed") == 0o770


def test_runs_once_per_working_directory(fresh_cwd, mocker):
    app_module._ensure_storage_dirs()
    spy = mocker.spy(app_module.os, "makedirs")
    app_module._ensure_storage_dirs()
    app_module._ensure_storage_dirs()
    spy.assert_not_called()


def test_new_working_directory_gets_its_own_dirs(fresh_cwd, tmp_path_factory, monkeypatch):
    app_module._ensure_storage_dirs()
    other = tmp_path_factory.mktemp("other")
    monkeypatch.chdir(other)
    app_module._ensure_storage_dirs()
    assert (other / "archive").is_dir() and (other / "failed").is_dir()


def test_existing_dirs_keep_their_permissions(fresh_cwd):
    (fresh_cwd / "archive").mkdir(mode=0o750)
    os.chmod(fresh_cwd / "archive", 0o750)
    app_module._ensure_storage_dirs()
    assert _mode(fresh_cwd / "archive") == 0o750  # operator's choice is not overridden
    assert _mode(fresh_cwd / "failed") == 0o770


def test_request_path_uses_it(client, mocker):
    ensure = mocker.patch("app._ensure_storage_dirs")
    client.post("/mailfetch", data={}, content_type="multipart/form-data")
    ensure.assert_called_once()
