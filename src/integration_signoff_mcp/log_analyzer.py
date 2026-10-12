"""Checks over the merchant's API request/response logs from sandbox testing.

Accepted input: a JSON array or JSON Lines. Each entry describes one API call.
Field names are flexible; these are recognised:

    timestamp            ISO 8601 string or epoch seconds
    method               GET, POST, ...
    url | path | endpoint
    status | status_code | response_status   (null or missing = timeout / no response)
    request_headers | headers
    request_body | body                      (object or JSON string)
    response_body | response                 (object or JSON string)
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse

from .models import Finding

AREA = "api"

CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
SENSITIVE_KEYS = re.compile(r"^(cvv|cvc|cvv2|card_?number|pan|pin|upi_?pin|otp)$", re.I)
SECRET_HEADER = re.compile(r"^(authorization|x-api-key|api-key|x-api-secret)$", re.I)


# ---------------------------------------------------------------- parsing


def parse_logs(text: str) -> list[dict]:
    text = text.strip()
    if not text:
        raise ValueError("The log input is empty.")
    if text.startswith("["):
        entries = json.loads(text)
    else:
        entries = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise ValueError("Logs must be a JSON array of objects or JSON Lines.")
    return [_normalise(entry, index) for index, entry in enumerate(entries)]


def _json_or_raw(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _timestamp(value) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value / 1000 if value > 1e12 else value)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _normalise(entry: dict, index: int) -> dict:
    url = entry.get("url") or entry.get("path") or entry.get("endpoint") or ""
    parsed = urlparse(url)
    status = entry.get("status", entry.get("status_code", entry.get("response_status")))
    headers = entry.get("request_headers") or entry.get("headers") or {}
    return {
        "index": index,
        "ts": _timestamp(entry.get("timestamp")),
        "method": str(entry.get("method", "GET")).upper(),
        "url": url,
        "host": parsed.hostname or "",
        "path": parsed.path or url,
        "status": int(status) if status not in (None, "") else None,
        "headers": {str(k).lower(): v for k, v in headers.items()},
        "request": _json_or_raw(entry.get("request_body", entry.get("body"))),
        "response": _json_or_raw(entry.get("response_body", entry.get("response"))),
    }


def _get(body, field: str):
    """Look up a field at the top level or one level down (e.g. under 'data')."""
    if not isinstance(body, dict):
        return None
    if field in body:
        return body[field]
    for value in body.values():
        if isinstance(value, dict) and field in value:
            return value[field]
    return None


def _luhn(digits: str) -> bool:
    total = 0
    for position, char in enumerate(reversed(digits)):
        number = int(char)
        if position % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def _mask(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return f"{digits[:4]}{'*' * (len(digits) - 8)}{digits[-4:]}" if len(digits) > 8 else "****"


def _walk(body, path=""):
    if isinstance(body, dict):
        for key, value in body.items():
            yield from _walk(value, f"{path}.{key}" if path else str(key))
    elif isinstance(body, list):
        for i, value in enumerate(body):
            yield from _walk(value, f"{path}[{i}]")
    else:
        yield path, body


# ---------------------------------------------------------------- checks


def analyse(text: str, profile: dict) -> list[Finding]:
    cfg = profile["api"]
    entries = parse_logs(text)
    create_re = re.compile(cfg["create_payment_path"])
    status_re = re.compile(cfg["status_check_path"])
    refund_re = re.compile(cfg["refund_path"])
    idem_header = cfg["idempotency_header"].lower()
    ref_field, amount_field, id_field = cfg["reference_field"], cfg["amount_field"], cfg["payment_id_field"]

    creates = [e for e in entries if e["method"] == "POST" and create_re.search(e["path"])]
    refunds = [e for e in entries if e["method"] == "POST" and refund_re.search(e["path"])]
    status_checks = [e for e in entries if e["method"] == "GET" and status_re.search(e["path"])]

    findings: list[Finding] = [
        Finding(
            "A01", AREA, "info", "pass", "Logs parsed",
            f"{len(entries)} calls: {len(creates)} payment creates, {len(status_checks)} status checks, "
            f"{len(refunds)} refunds.",
        )
    ]

    if not creates:
        findings.append(
            Finding(
                "A02", AREA, "major", "fail", "Logs contain payment-create calls",
                "No calls matched the create-payment path pattern "
                f"({cfg['create_payment_path']}).",
                "Export the full sandbox test run, or set api.create_payment_path in the profile to match the "
                "gateway's endpoint.",
            )
        )
        return findings

    # A03 environment
    hosts = sorted({e["host"] for e in entries if e["host"]})
    live_hosts = [h for h in hosts if not any(marker in h for marker in cfg["sandbox_hosts"])]
    findings.append(
        Finding(
            "A03", AREA, "info", "warn" if live_hosts else "pass", "Testing ran against a sandbox host",
            f"Hosts seen: {', '.join(hosts) or 'none (paths only)'}.",
            "Confirm these hosts are the sandbox environment." if live_hosts else "",
        )
    )

    # A04 idempotency keys on writes
    writes = creates + refunds
    missing = [e for e in writes if not e["headers"].get(idem_header)]
    findings.append(
        Finding(
            "A04", AREA, "major", "fail" if missing else "pass",
            f"Write calls send an {cfg['idempotency_header']} header",
            f"{len(writes) - len(missing)} of {len(writes)} create/refund calls carry the header.",
            "" if not missing else "Send a unique idempotency key per logical operation and reuse it on retries.",
            {"log_lines_missing_key": [e["index"] for e in missing][:20]},
        )
    )

    # A05 unique references and A06 retries reuse the key
    by_reference: dict[str, list[dict]] = defaultdict(list)
    for entry in creates:
        reference = _get(entry["request"], ref_field)
        if reference is not None:
            by_reference[str(reference)].append(entry)

    conflicting, duplicated, bad_retries = [], [], []
    for reference, calls in by_reference.items():
        amounts = {json.dumps(_get(c["request"], amount_field)) for c in calls}
        if len(amounts) > 1:
            conflicting.append(reference)
        successful_keys = {c["headers"].get(idem_header) for c in calls if c["status"] and 200 <= c["status"] < 300}
        if len(successful_keys) > 1:
            duplicated.append(reference)
        ordered = sorted(calls, key=lambda c: (c["ts"] or 0, c["index"]))
        for previous, current in zip(ordered, ordered[1:]):
            failed_transiently = previous["status"] is None or previous["status"] >= 500
            if failed_transiently and previous["headers"].get(idem_header) != current["headers"].get(idem_header):
                bad_retries.append(reference)

    references_present = bool(by_reference)
    if not references_present:
        findings.append(
            Finding(
                "A05", AREA, "major", "fail", "Each order uses a unique reference",
                f"No '{ref_field}' field found in create requests.",
                f"Send your own order id in '{ref_field}' so payments can be reconciled to orders.",
            )
        )
    else:
        status = "fail" if conflicting else ("fail" if duplicated else "pass")
        severity = "blocker" if conflicting else "major"
        detail = []
        if conflicting:
            detail.append(f"Same reference sent with different amounts: {', '.join(conflicting[:5])}.")
        if duplicated:
            detail.append(f"Same reference created successfully more than once: {', '.join(duplicated[:5])}.")
        findings.append(
            Finding(
                "A05", AREA, severity, status, "Each order uses a unique reference",
                " ".join(detail) or f"{len(by_reference)} distinct references, none reused.",
                "" if status == "pass" else "Generate one reference per order and never reuse it for a new payment.",
            )
        )

    findings.append(
        Finding(
            "A06", AREA, "major", "fail" if bad_retries else "pass",
            "Retries after timeouts or 5xx reuse the idempotency key",
            f"Retries with a new key for: {', '.join(sorted(set(bad_retries))[:5])}." if bad_retries
            else "No retry used a fresh key after a transient failure.",
            "" if not bad_retries else "On a timeout or 5xx, retry with the same idempotency key, or check status "
            "first. A new key can create a second charge.",
        )
    )

    # A07 amount units
    bad_amounts = []
    for entry in writes:
        amount = _get(entry["request"], amount_field)
        if amount is None:
            continue
        if cfg["amount_unit"] == "minor":
            is_integer = isinstance(amount, int) and not isinstance(amount, bool)
            if not is_integer:
                bad_amounts.append((entry["index"], amount))
    findings.append(
        Finding(
            "A07", AREA, "major", "fail" if bad_amounts else "pass",
            "Amounts are sent in the expected unit",
            f"Non-integer amounts at log lines {[i for i, _ in bad_amounts][:10]}: "
            f"{[a for _, a in bad_amounts][:5]}." if bad_amounts
            else f"All amounts are integers in the smallest currency unit ({cfg['amount_unit']}).",
            "" if not bad_amounts else "Send amounts as integers in the smallest unit (₹10.50 = 1050 paise). "
            "Never use floating point for money.",
        )
    )

    # A08 status check after create
    created_ids = []
    for entry in creates:
        if entry["status"] and 200 <= entry["status"] < 300:
            payment_id = _get(entry["response"], id_field)
            if payment_id is not None:
                created_ids.append((str(payment_id), entry))
    checked = set()
    polls: dict[str, list[float]] = defaultdict(list)
    for entry in status_checks:
        match = status_re.search(entry["path"])
        payment_id = match.groupdict().get("id") if match else None
        if payment_id:
            polls[payment_id].append(entry["ts"] or 0)
            for created_id, create in created_ids:
                if created_id == payment_id and (entry["ts"] or 0) >= (create["ts"] or 0):
                    checked.add(created_id)
    unchecked = [pid for pid, _ in created_ids if pid not in checked]
    if created_ids:
        findings.append(
            Finding(
                "A08", AREA, "major", "fail" if unchecked else "pass",
                "Payment status is confirmed server-to-server",
                f"{len(created_ids) - len(unchecked)} of {len(created_ids)} created payments had a later status "
                "check." + (f" Never checked: {', '.join(unchecked[:5])}." if unchecked else ""),
                "" if not unchecked else "Before fulfilling, call the status API from your server. Do not rely on "
                "the browser redirect or callback alone.",
            )
        )
    else:
        findings.append(
            Finding(
                "A08", AREA, "info", "skipped", "Payment status is confirmed server-to-server",
                f"Could not read a payment id ('{id_field}') from create responses.",
            )
        )

    # A09 polling rate
    limit = cfg["max_status_polls_per_minute"]
    aggressive = []
    for payment_id, times in polls.items():
        times = sorted(t for t in times if t)
        for i in range(len(times)):
            window = [t for t in times[i:] if t - times[i] < 60]
            if len(window) > limit:
                aggressive.append(payment_id)
                break
    findings.append(
        Finding(
            "A09", AREA, "minor", "warn" if aggressive else "pass", "Status polling is rate-limited",
            f"More than {limit} status checks a minute for: {', '.join(aggressive[:5])}." if aggressive
            else f"No payment was polled more than {limit} times a minute.",
            "" if not aggressive else "Poll with backoff (for example 5 s, 10 s, 30 s, then every minute) and rely "
            "on webhooks for the final state.",
        )
    )

    # A10 repeated identical client errors
    errors: dict[tuple, int] = defaultdict(int)
    for entry in entries:
        if entry["status"] and 400 <= entry["status"] < 500 and entry["status"] not in (401, 404, 409):
            errors[(entry["method"], entry["path"], entry["status"])] += 1
    repeated = {k: v for k, v in errors.items() if v >= 5}
    findings.append(
        Finding(
            "A10", AREA, "minor", "warn" if repeated else "pass", "Validation errors are handled, not repeated",
            "; ".join(f"{m} {p} returned {s} x{n}" for (m, p, s), n in list(repeated.items())[:5]) if repeated
            else "No validation error repeated five or more times.",
            "" if not repeated else "Map 4xx errors to fixes in the request instead of resending the same call.",
        )
    )

    # A11 sensitive data in requests/responses
    card_hits, key_hits, secret_headers = [], [], set()
    for entry in entries:
        for header in entry["headers"]:
            if SECRET_HEADER.match(header):
                secret_headers.add(header)
        for body in (entry["request"], entry["response"]):
            for path, value in _walk(body):
                key = path.rsplit(".", 1)[-1]
                if SENSITIVE_KEYS.match(key) and value not in (None, ""):
                    key_hits.append(f"line {entry['index']}: {path}")
                if isinstance(value, (str, int)) and not isinstance(value, bool):
                    for match in CARD_CANDIDATE.finditer(str(value)):
                        digits = re.sub(r"\D", "", match.group())
                        if 13 <= len(digits) <= 19 and _luhn(digits):
                            card_hits.append(f"line {entry['index']}: {path} = {_mask(match.group())}")
    sensitive = card_hits + key_hits
    findings.append(
        Finding(
            "A11", AREA, "blocker", "fail" if sensitive else "pass", "No card data or PINs in logged traffic",
            ("Found: " + "; ".join(sensitive[:8])) if sensitive else "No card numbers, CVVs, PINs or OTPs found.",
            "" if not sensitive else "Never log or send raw card data or PINs from your servers. Use the gateway's "
            "hosted fields or tokenisation, and mask sensitive fields in logs.",
        )
    )
    findings.append(
        Finding(
            "A12", AREA, "minor", "warn" if secret_headers else "pass", "API credentials are redacted in logs",
            f"Credential headers present in the export: {', '.join(sorted(secret_headers))}." if secret_headers
            else "No credential headers in the export.",
            "" if not secret_headers else "Redact Authorization and API key headers before writing logs, and rotate "
            "any key that was shared in this export.",
        )
    )

    # A13 refund coverage
    findings.append(
        Finding(
            "A13", AREA, "minor", "pass" if refunds else "warn", "Refund API was exercised",
            f"{len(refunds)} refund calls." if refunds else "No refund calls in the logs.",
            "" if refunds else "Test full and partial refunds in sandbox before go-live.",
        )
    )

    return findings
