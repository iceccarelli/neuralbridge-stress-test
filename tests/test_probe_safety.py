import pytest

from scripts.probe_staging import validate_base_url


@pytest.mark.parametrize(
    "url",
    [
        "https://neuralbridge.io",
        "https://www.neuralbridge.io",
        "https://assurance-register.fly.dev",
        "https://x.neuralbridge.io",
    ],
)
def test_probe_refuses_known_production_hosts(url):
    with pytest.raises(ValueError):
        validate_base_url(url)


def test_probe_requires_https_for_non_loopback_hosts():
    with pytest.raises(ValueError):
        validate_base_url("http://staging.example.com")


def test_probe_allows_https_staging_hosts():
    assert validate_base_url("https://staging.example.net/") == "https://staging.example.net"


def test_probe_allows_localhost_for_local_api_work():
    assert validate_base_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"


def test_probe_rejects_credentials_in_base_url():
    with pytest.raises(ValueError):
        validate_base_url("https://user:pass@staging.example.net")
