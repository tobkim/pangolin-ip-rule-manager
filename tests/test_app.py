import contextlib
import http.client
import importlib
import threading

import pytest


@contextlib.contextmanager
def start_server(handler_cls):
    from http.server import HTTPServer

    httpd = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = httpd.server_port

    t = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    t.start()
    try:
        yield (httpd, port)
    finally:
        httpd.shutdown()
        t.join(timeout=5)


@pytest.fixture
def temp_state_file(tmp_path):
    # create an empty temp state file path
    p = tmp_path / "state.json"
    return str(p)


@pytest.fixture
def app_module(monkeypatch, temp_state_file):
    # Ensure env is set before import
    monkeypatch.setenv("PANGOLIN_TOKEN", "")  # avoid network calls in ensure_ip_rule
    monkeypatch.setenv("RESOURCE_IDS", "5")
    monkeypatch.setenv("LISTEN_PORT", "0")
    monkeypatch.setenv("STATE_FILE", temp_state_file)
    # Mandatory custom header configuration
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", "X-Test-Key")
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", "v123")

    # Import or reload module to apply env
    if "app" in globals():
        import app as _app
        app = importlib.reload(_app)
    else:
        import app  # type: ignore
    # Reset runtime state
    with app.state_lock:
        app.state.clear()
    with app.state_lock:
        app.rules_cache.clear()
    return app


def test_banner_serves_png_and_updates_state(app_module):
    app = app_module

    test_ip = "1.2.3.4"

    with start_server(app.BannerHandler) as (httpd, port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {
            "X-Real-IP": test_ip,
            app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE,
            # Remote-User is optional; include to ensure logging path works
            "Remote-User": "alice",
        }
        conn.request("GET", "/banner.png", headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        assert data == app.BANNER_PNG

    # state should have been updated for the real ip
    with app.state_lock:
        assert test_ip in app.state
        rec = app.state[test_ip]
        assert isinstance(rec.get("resources"), dict)
        assert "last_seen" in rec


def test_security_header_enforced(monkeypatch, temp_state_file):
    # Set required header env and reload module
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", "X-Test-Key")
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", "v123")
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "8")
    monkeypatch.setenv("STATE_FILE", temp_state_file)

    import app as _app
    app = importlib.reload(_app)
    with app.state_lock:
        app.state.clear()

    with start_server(app.BannerHandler) as (httpd, port):
        # Missing header -> 403
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/banner.png")
        resp = conn.getresponse()
        _ = resp.read()
        assert resp.status == 403

        # With correct custom header -> 200
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {app.EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY: app.EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE}
        conn.request("GET", "/banner.png", headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        assert resp.status == 200
        assert data == app.BANNER_PNG


def test_rules_cache_uses_cache(monkeypatch, app_module):
    app = app_module

    calls = {"count": 0}

    def fake_http_json(method, url, body=None):
        calls["count"] += 1
        assert method == "GET"
        assert "/rules" in url
        return {"data": {"rules": [
            {"match": "IP", "value": "9.8.7.6"},
            {"match": "IP", "value": "1.2.3.4"},
        ]}}

    monkeypatch.setattr(app, "http_json", fake_http_json)

    # First call should hit http_json
    s1 = app._get_ip_set_for_resource_cached(5)
    assert "9.8.7.6" in s1
    assert calls["count"] == 1

    # Second call within TTL should use cache
    s2 = app._get_ip_set_for_resource_cached(5)
    assert "1.2.3.4" in s2
    assert calls["count"] == 1


def test_cleanup_once_removes_expired_ips(monkeypatch, app_module):
    app = app_module

    # Make everything immediately expired
    monkeypatch.setattr(app, "RETENTION_MINUTES", 0)

    # Insert an old record created by us
    old_ip = "5.5.5.5"
    with app.state_lock:
        app.state[old_ip] = {
            "last_seen": "2000-01-01T00:00:00Z",
            "resources": {"3": {"created_by_us": True}}
        }

    # Do not perform real HTTP calls for deletion; pretend success
    monkeypatch.setattr(app, "delete_ip_rule_if_created_by_us", lambda ip, rid: True)

    app.cleanup_old_ips()

    with app.state_lock:
        assert old_ip not in app.state


def test_security_header_misconfigured_only_key(monkeypatch, temp_state_file):
    # Only key is set -> since custom header is mandatory, importing app should fail
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", "X-Only-Key")
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", "")
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "8")
    monkeypatch.setenv("STATE_FILE", temp_state_file)

    import app as _app
    with pytest.raises(RuntimeError):
        importlib.reload(_app)


def test_security_header_misconfigured_only_value(monkeypatch, temp_state_file):
    # Only value is set -> importing app should fail
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_KEY", "")
    monkeypatch.setenv("EXPECTED_PANGOLIN_CUSTOM_HEADER_VALUE", "v123")
    monkeypatch.setenv("PANGOLIN_TOKEN", "")
    monkeypatch.setenv("RESOURCE_IDS", "8")
    monkeypatch.setenv("STATE_FILE", temp_state_file)

    import app as _app
    with pytest.raises(RuntimeError):
        importlib.reload(_app)
