from unittest.mock import Mock

import pytest

from onionshare_cli import censorship, common, onion


class FakeMeek:
    """Stands in for a running meek-client, so api_proxies is populated."""

    meek_proxies = {
        "http": "socks5h://127.0.0.1:1",
        "https": "socks5h://127.0.0.1:1",
    }


class FakeResponse:
    status_code = 200

    def json(self):
        return {"settings": []}


class FakeUnauthenticatedOnion:
    def __init__(self):
        self.authentication_checks = 0

    def is_authenticated(self):
        self.authentication_checks += 1
        return False

    def get_tor_socks_port(self):
        raise AssertionError("The Tor proxy must not be used when unauthenticated")


@pytest.fixture
def circumvention_obj():
    return censorship.CensorshipCircumvention(common.Common(), FakeMeek())


@pytest.fixture
def captured_request(monkeypatch):
    """Capture the request body that would go to the Moat API."""
    captured = {}

    def fake_post(endpoint, json=None, headers=None, proxies=None):
        captured["endpoint"] = endpoint
        captured["json"] = json
        return FakeResponse()

    monkeypatch.setattr(censorship.requests, "post", fake_post)
    return captured


class TestRequestSettings:
    def test_country_is_sent(self, circumvention_obj, captured_request):
        circumvention_obj.request_settings(country="de")
        assert captured_request["json"] == {"country": "de"}

    def test_transports_are_sent(self, circumvention_obj, captured_request):
        circumvention_obj.request_settings(
            country="de", transports=["obfs4", "snowflake"]
        )
        assert captured_request["json"] == {
            "country": "de",
            "transports": ["obfs4", "snowflake"],
        }

    def test_transports_are_sent_without_a_country(
        self, circumvention_obj, captured_request
    ):
        circumvention_obj.request_settings(transports=["obfs4"])
        assert captured_request["json"] == {"transports": ["obfs4"]}


def test_unauthenticated_onion_does_not_configure_a_tor_proxy():
    fake_onion = FakeUnauthenticatedOnion()

    circumvention = censorship.CensorshipCircumvention(
        common.Common(), onion=fake_onion
    )

    assert fake_onion.authentication_checks == 1
    assert circumvention.api_proxies == {}


def test_bridge_update_skips_tor_when_unauthenticated(monkeypatch):
    fake_onion = onion.Onion.__new__(onion.Onion)
    fake_onion.common = Mock()
    fake_onion.settings = Mock()
    fake_onion.is_authenticated = Mock(return_value=False)

    class FakeMeek:
        def __init__(self, common):
            pass

        def start(self):
            pass

        def cleanup(self):
            pass

    class FakeCensorshipCircumvention:
        def __init__(self, common, meek=None, onion=None):
            assert onion is None

        def request_builtin_bridges(self):
            return ["obfs4 bridge"]

    monkeypatch.setattr(onion, "Meek", FakeMeek)
    monkeypatch.setattr(onion, "CensorshipCircumvention", FakeCensorshipCircumvention)

    fake_onion.update_builtin_bridges()

    fake_onion.is_authenticated.assert_called_once_with()
    fake_onion.settings.set.assert_called_once_with("bridges_builtin", ["obfs4 bridge"])
    fake_onion.settings.save.assert_called_once_with()
