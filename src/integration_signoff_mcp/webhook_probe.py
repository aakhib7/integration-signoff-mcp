"""Active checks against a merchant's webhook endpoint.

The probe sends signed test events, plus deliberately bad ones, and checks how
the endpoint responds. Point it at the merchant's sandbox/UAT endpoint: the
valid events are well formed and a careless handler may act on them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import socket
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from urllib.parse import urlparse

from .models import Finding

AREA = "webhook"


@dataclass
class Response:
    status: int | None
    elapsed_ms: int
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def rejected(self) -> bool:
        return self.status is not None and 400 <= self.status < 500

    def describe(self) -> str:
        if self.status is None:
            return f"no response ({self.error})"
        return f"HTTP {self.status} in {self.elapsed_ms} ms"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 - urllib hook
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


def sign(secret: str, payload: str, algorithm: str = "sha256", encoding: str = "hex") -> str:
    digest = hmac.new(secret.encode(), payload.encode(), getattr(hashlib, algorithm)).digest()
    if encoding == "base64":
        return base64.b64encode(digest).decode()
    return digest.hex()


def build_event(event_type: str, event_id: str | None = None) -> dict:
    payment_suffix = uuid.uuid4().hex[:12]
    return {
        "id": event_id or f"evt_signoff_{uuid.uuid4().hex[:16]}",
        "type": event_type,
        "created_at": int(time.time()),
        "test": True,
        "data": {
            "id": f"pay_signoff_{payment_suffix}",
            "reference_id": f"signoff-test-{payment_suffix}",
            "amount": 100,
            "currency": "INR",
            "status": "succeeded",
        },
    }


def check_target(url: str, allow_private: bool) -> str | None:
    """Return an error message if the URL must not be probed."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return "URL must be an absolute http(s) URL."
    if allow_private:
        return None
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        return f"Could not resolve {parsed.hostname}: {exc}"
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
            return (
                f"{parsed.hostname} resolves to a private address ({address}). "
                "Set allow_private=true only for an endpoint you control."
            )
    return None


class Prober:
    def __init__(self, url: str, secret: str, profile: dict, timeout: float = 10.0):
        self.url = url
        self.secret = secret
        self.cfg = profile["webhook"]
        self.timeout = timeout

    def headers_for(self, body: str, event_id: str, timestamp: int, signature: str | None) -> dict:
        headers = {"Content-Type": "application/json", "User-Agent": "integration-signoff-mcp/0.1"}
        if self.cfg.get("timestamp_header"):
            headers[self.cfg["timestamp_header"]] = str(timestamp)
        if self.cfg.get("event_id_header"):
            headers[self.cfg["event_id_header"]] = event_id
        if signature is not None:
            headers[self.cfg["signature_header"]] = signature
        return headers

    def signature_for(self, body: str, event_id: str, timestamp: int, secret: str | None = None) -> str:
        payload = self.cfg["signed_payload"].format(timestamp=timestamp, event_id=event_id, body=body)
        return sign(secret or self.secret, payload, self.cfg["algorithm"], self.cfg["encoding"])

    def post(self, body: str, headers: dict) -> Response:
        request = urllib.request.Request(self.url, data=body.encode(), headers=headers, method="POST")
        start = time.monotonic()
        try:
            with _OPENER.open(request, timeout=self.timeout) as resp:
                resp.read(65536)
                return Response(resp.status, int((time.monotonic() - start) * 1000))
        except urllib.error.HTTPError as exc:
            return Response(exc.code, int((time.monotonic() - start) * 1000))
        except Exception as exc:  # network errors, timeouts, TLS failures
            return Response(None, int((time.monotonic() - start) * 1000), error=f"{type(exc).__name__}: {exc}")

    def send(
        self,
        event: dict | None = None,
        raw_body: str | None = None,
        signature: str | None | bool = True,
        timestamp: int | None = None,
    ) -> Response:
        """Send one delivery. signature=True signs correctly, False omits it, a string is sent as is."""
        event = event or build_event(self.cfg["success_event_type"])
        body = raw_body if raw_body is not None else json.dumps(event, separators=(",", ":"))
        ts = timestamp if timestamp is not None else int(time.time())
        if signature is True:
            sig = self.signature_for(body, event["id"], ts)
        elif signature is False:
            sig = None
        else:
            sig = signature
        return self.post(body, self.headers_for(body, event["id"], ts, sig))


def _finding(check_id, severity, passed, title, detail, fix, evidence=None, warn=False) -> Finding:
    status = "pass" if passed else ("warn" if warn else "fail")
    return Finding(check_id, AREA, severity, status, title, detail, "" if passed else fix, evidence or {})


def probe(url: str, secret: str, profile: dict, allow_private: bool = False, timeout: float = 10.0) -> list[Finding]:
    """Run every webhook check and return the findings."""
    blocked = check_target(url, allow_private)
    if blocked:
        return [
            Finding("W00", AREA, "blocker", "fail", "Endpoint can be probed", blocked, "Provide a public HTTPS URL.")
        ]

    cfg = profile["webhook"]
    prober = Prober(url, secret, profile, timeout)
    findings: list[Finding] = []

    # W01 HTTPS
    is_https = urlparse(url).scheme == "https"
    findings.append(
        _finding(
            "W01",
            "blocker",
            is_https,
            "Endpoint uses HTTPS",
            "HTTPS endpoint." if is_https else "Endpoint is plain HTTP; payment events would travel unencrypted.",
            "Serve the webhook endpoint over HTTPS with a valid certificate.",
            warn=not is_https and allow_private,
        )
    )

    # W02 valid event accepted
    valid_event = build_event(cfg["success_event_type"])
    valid = prober.send(valid_event)
    redirect = valid.status is not None and 300 <= valid.status < 400
    findings.append(
        _finding(
            "W02",
            "blocker",
            valid.ok,
            "Correctly signed event is acknowledged with 2xx",
            valid.describe() + (" (redirects are not followed by gateways)" if redirect else ""),
            "Return 2xx quickly for valid events. Do not redirect; acknowledge first, process asynchronously.",
            {"status": valid.status, "elapsed_ms": valid.elapsed_ms},
        )
    )

    if valid.status is None:
        skip = "Skipped: the endpoint did not respond to a valid event."
        for check_id, title in [
            ("W03", "Responds within the gateway timeout"),
            ("W04", "Rejects an invalid signature"),
            ("W05", "Rejects a missing signature"),
            ("W06", "Rejects a replayed (stale) event"),
            ("W07", "Acknowledges duplicate deliveries"),
            ("W08", "Acknowledges unknown event types"),
            ("W09", "Handles a malformed body without a server error"),
        ]:
            findings.append(Finding(check_id, AREA, "info", "skipped", title, skip))
        return findings

    # W03 latency
    elapsed = valid.elapsed_ms
    too_slow = elapsed > cfg["max_response_ms"]
    slow = elapsed > cfg["slow_response_ms"]
    findings.append(
        Finding(
            "W03",
            AREA,
            "major",
            "fail" if too_slow else ("warn" if slow else "pass"),
            "Responds within the gateway timeout",
            f"{elapsed} ms (limit {cfg['max_response_ms']} ms, target under {cfg['slow_response_ms']} ms).",
            "" if not slow else "Acknowledge immediately and move processing to a queue or background job.",
            {"elapsed_ms": elapsed},
        )
    )

    # W04 invalid signature
    bad_sig = prober.send(signature=prober.signature_for("tampered", "evt", 0, secret="wrong-secret"))
    findings.append(
        _finding(
            "W04",
            "blocker",
            bad_sig.rejected,
            "Rejects an invalid signature",
            bad_sig.describe(),
            "Verify the signature header on every delivery and return 401/400 when it does not match. "
            "Compute the HMAC over the raw request body and compare in constant time.",
            {"status": bad_sig.status},
        )
    )

    # W05 missing signature
    no_sig = prober.send(signature=False)
    findings.append(
        _finding(
            "W05",
            "blocker",
            no_sig.rejected,
            "Rejects a missing signature",
            no_sig.describe(),
            "Treat a missing signature header as invalid and return 401/400.",
            {"status": no_sig.status},
        )
    )

    # W06 replay protection
    signs_timestamp = "{timestamp}" in cfg["signed_payload"] and cfg.get("timestamp_header")
    if signs_timestamp:
        stale_ts = int(time.time()) - cfg["replay_window_seconds"] * 3
        stale = prober.send(timestamp=stale_ts)
        findings.append(
            _finding(
                "W06",
                "major",
                stale.rejected,
                "Rejects a replayed (stale) event",
                f"Event signed {cfg['replay_window_seconds'] * 3} s ago: {stale.describe()}",
                f"Reject events whose timestamp is more than {cfg['replay_window_seconds']} s old.",
                {"status": stale.status},
            )
        )
    else:
        findings.append(
            Finding("W06", AREA, "info", "skipped", "Rejects a replayed (stale) event",
                    "Skipped: the profile's signature does not include a timestamp.")
        )

    # W07 duplicate delivery
    duplicate_event = build_event(cfg["success_event_type"])
    first = prober.send(duplicate_event)
    second = prober.send(duplicate_event)
    findings.append(
        _finding(
            "W07",
            "major",
            first.ok and second.ok,
            "Acknowledges duplicate deliveries",
            f"Same event id sent twice: first {first.describe()}, second {second.describe()}. "
            "Confirm in the merchant's logs that the order was fulfilled only once.",
            "Gateways retry deliveries. Store processed event ids and return 2xx for repeats without re-processing.",
            {"event_id": duplicate_event["id"], "statuses": [first.status, second.status]},
        )
    )

    # W08 unknown event type
    unknown = prober.send(build_event("signoff.unknown_event_type"))
    findings.append(
        _finding(
            "W08",
            "minor",
            unknown.ok,
            "Acknowledges unknown event types",
            unknown.describe(),
            "Return 2xx for event types you do not handle, so new event types do not cause retry storms.",
            {"status": unknown.status},
        )
    )

    # W09 malformed body
    malformed = prober.send(event=build_event(cfg["success_event_type"]), raw_body="{not json")
    handled = malformed.status is not None and malformed.status < 500
    findings.append(
        _finding(
            "W09",
            "minor",
            handled,
            "Handles a malformed body without a server error",
            malformed.describe(),
            "Validate the body and return 400 for unparseable payloads instead of crashing.",
            {"status": malformed.status},
        )
    )

    return findings
