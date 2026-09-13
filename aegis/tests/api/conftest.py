"""Isolate durable ledgers for API tests; production never auto-initializes one."""

import pytest

from aegis.adapters.authorization_store import initialize_database


@pytest.fixture(autouse=True)
def authorization_database(monkeypatch, tmp_path):
    path = tmp_path / "authorization.sqlite3"
    initialize_database(path)
    monkeypatch.setenv("AEGIS_AUTHORIZATION_DB_PATH", str(path))
    monkeypatch.setenv("AEGIS_CONTROL_DB_PATH", str(tmp_path / "controls-default.sqlite3"))
