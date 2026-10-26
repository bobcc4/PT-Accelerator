from copy import deepcopy
from unittest.mock import Mock

import pytest

from app.routes import ikuai


@pytest.fixture
def settings(monkeypatch):
    class Config:
        def __init__(self):
            self._data = {"ikuai": {"enabled": True, "host": "https://router.test",
                "api_version": "v4", "token": "encrypted:saved", "verify_tls": False}}

        def get(self, key, default=None):
            section, field = key.split(".")
            return self._data.get(section, {}).get(field, default)

        def set(self, key, value):
            section, field = key.split(".")
            self._data.setdefault(section, {})[field] = value

        def save(self):
            pass

    config = Config()
    factory = Mock()
    factory.return_value.test_connection.return_value = (True, "connected")
    monkeypatch.setattr(ikuai, "config", config)
    monkeypatch.setattr(ikuai, "create_ikuai_service", factory)
    monkeypatch.setattr(ikuai, "encrypt_secret", lambda x: "encrypted:" + x)
    monkeypatch.setattr(ikuai, "decrypt_secret", lambda x: x.removeprefix("encrypted:"))
    return config, factory


def test_token_is_encrypted_masked_and_preserved(settings):
    config, factory = settings
    assert ikuai.save_config({"enabled": True, "host": "router.test", "api_version": "v4",
                              "token": "new-token", "verify_tls": False})["success"]
    assert config.get("ikuai.token") == "encrypted:new-token"
    assert ikuai.get_status()["token"] == "********"
    assert factory.call_args.kwargs["token"] == "new-token"
    assert factory.call_args.kwargs["host"] == "https://router.test"
    assert ikuai.save_config({"enabled": True, "host": "router.test", "token": "********"})["success"]
    assert config.get("ikuai.token") == "encrypted:new-token"
    assert factory.call_args.kwargs["token"] == "new-token"


def test_test_connection_uses_saved_token(settings):
    _, factory = settings
    assert ikuai.test_connection({"enabled": True, "token": "********"})["success"]
    assert factory.call_args.kwargs["token"] == "saved"
    assert factory.call_args.kwargs["verify_tls"] is False


def test_http_v4_is_rejected_without_changing_config(settings):
    config, factory = settings
    before = deepcopy(config._data)
    assert not ikuai.save_config({"enabled": True, "api_version": "v4", "host": "http://router.test"})["success"]
    assert config._data == before
    factory.assert_not_called()


def test_read_error_is_not_empty_success(settings):
    _, factory = settings
    factory.return_value.get_dns_records.side_effect = ValueError("failed")
    assert not ikuai.get_records()["success"]
    factory.return_value.close.assert_called_once()


def test_automatic_pipeline_uses_decrypted_v4_credentials(settings, monkeypatch):
    from app.pipelines import hosts_pipeline

    config, factory = settings
    monkeypatch.setattr(hosts_pipeline, "config", config)
    monkeypatch.setattr(hosts_pipeline, "create_ikuai_service", factory)
    monkeypatch.setattr(hosts_pipeline, "decrypt_secret", lambda x: x.removeprefix("encrypted:"))
    assert hosts_pipeline.HostsPipeline._create_ikuai_service() is factory.return_value
    assert factory.call_args.kwargs["api_version"] == "v4"
    assert factory.call_args.kwargs["token"] == "saved"
    assert factory.call_args.kwargs["verify_tls"] is False
