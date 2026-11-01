"""Issue #67: fail fast on missing config in production, stay lenient elsewhere."""
import pytest
from flask import Flask

import app as app_module

GOOD = 'MAILGUN_API_KEY = "k"\nMAILGUN_DOMAIN = "d"\nMAILGUN_RECIPIENT = "r@x"\n'


def _flask(tmp_path, config_text=None):
    if config_text is not None:
        (tmp_path / "config.py").write_text(config_text)
    return Flask("t", instance_path=str(tmp_path), instance_relative_config=True)


@pytest.mark.parametrize("value, expected", [
    ("production", True), (" Production ", True), ("", False), ("dev", False), (None, False),
])
def test_is_production(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("TMA_CONFIG", raising=False)
    else:
        monkeypatch.setenv("TMA_CONFIG", value)
    assert app_module.is_production() is expected


def test_production_missing_file_raises(tmp_path):
    with pytest.raises(OSError):
        app_module.load_config(_flask(tmp_path), production=True)


def test_production_missing_keys_raises_and_names_them(tmp_path):
    flask_app = _flask(tmp_path, 'MAILGUN_API_KEY = "k"\nMAILGUN_DOMAIN = ""\n')
    with pytest.raises(RuntimeError) as exc:
        app_module.load_config(flask_app, production=True)
    assert "MAILGUN_DOMAIN" in str(exc.value) and "MAILGUN_RECIPIENT" in str(exc.value)
    assert "MAILGUN_API_KEY" not in str(exc.value)


def test_production_complete_config_loads(tmp_path):
    flask_app = _flask(tmp_path, GOOD)
    app_module.load_config(flask_app, production=True)
    assert flask_app.config["MAILGUN_DOMAIN"] == "d"


def test_non_production_missing_file_is_silent(tmp_path):
    flask_app = _flask(tmp_path)
    app_module.load_config(flask_app, production=False)  # no exception
    assert "MAILGUN_API_KEY" not in flask_app.config


def test_non_production_partial_config_is_allowed(tmp_path):
    flask_app = _flask(tmp_path, 'MAILGUN_API_KEY = "k"\n')
    app_module.load_config(flask_app, production=False)
    assert flask_app.config["MAILGUN_API_KEY"] == "k"
