"""Project-root conftest: runs before any test module is imported.

Creates the Flask instance directory and an empty config.py so that
``app.config.from_pyfile("config.py")`` succeeds during test collection.
All real config values are injected by the ``app_config`` fixture in
``tests/conftest.py``.
"""
import os

# Run at module-import time (before tests/conftest.py is loaded) so that
# Flask's from_pyfile("config.py") succeeds when app.py is first imported.
_instance_dir = os.path.join(os.path.dirname(__file__), "instance")
os.makedirs(_instance_dir, exist_ok=True)
_config_path = os.path.join(_instance_dir, "config.py")
if not os.path.exists(_config_path):
    open(_config_path, "w").close()
