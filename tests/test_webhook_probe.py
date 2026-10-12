import base64
import hashlib
import hmac

from helpers import PROFILE, start_merchant, statuses

from integration_signoff_mcp import webhook_probe


def test_sign_matches_hmac_in_hex_and_base64():
    raw = hmac.new(b"secret", b"payload", hashlib.sha256).digest()
    assert webhook_probe.sign("secret", "payload") == raw.hex()
    assert webhook_probe.sign("secret", "payload", encoding="base64") == base64.b64encode(raw).decode()


def test_well_built_endpoint_passes_every_check():
    server, url = start_merchant("good")
    try:
        result = statuses(webhook_probe.probe(url, "demo-secret", PROFILE, allow_private=True))
    finally:
        server.shutdown()
    # Plain HTTP on localhost is a warning, not a pass.
    assert result.pop("W01") == "warn"
    assert set(result.values()) == {"pass"}


def test_endpoint_that_accepts_anything_fails_signature_checks():
    server, url = start_merchant("bad")
    try:
        result = statuses(webhook_probe.probe(url, "demo-secret", PROFILE, allow_private=True))
    finally:
        server.shutdown()
    assert result["W02"] == "pass"
    assert result["W04"] == "fail"
    assert result["W05"] == "fail"
    assert result["W06"] == "fail"


def test_wrong_secret_means_valid_events_are_rejected():
    server, url = start_merchant("good")
    try:
        result = statuses(webhook_probe.probe(url, "not-the-secret", PROFILE, allow_private=True))
    finally:
        server.shutdown()
    assert result["W02"] == "fail"


def test_private_addresses_are_refused_by_default():
    findings = webhook_probe.probe("http://127.0.0.1:9/webhook", "s", PROFILE)
    assert findings[0].check_id == "W00"
    assert findings[0].status == "fail"


def test_unreachable_endpoint_skips_dependent_checks():
    result = statuses(webhook_probe.probe("http://127.0.0.1:9/webhook", "s", PROFILE, allow_private=True, timeout=2))
    assert result["W02"] == "fail"
    assert result["W04"] == "skipped"
