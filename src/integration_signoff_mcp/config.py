"""Gateway-agnostic rules profile.

Every gateway names its headers, endpoints and fields differently. The defaults
below describe a typical REST payment API. Override any of them with a JSON file
whose path is in the SIGNOFF_PROFILE environment variable; keys you leave out
keep their default values.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

DEFAULT_PROFILE: dict = {
    "webhook": {
        # How the gateway signs webhooks. The probe signs test events the same way.
        "signature_header": "X-Signature",
        "timestamp_header": "X-Timestamp",
        "event_id_header": "X-Event-Id",
        "algorithm": "sha256",  # sha256 or sha512
        "encoding": "hex",  # hex or base64
        # What is signed. Placeholders: {timestamp}, {event_id}, {body}
        "signed_payload": "{timestamp}.{body}",
        "success_event_type": "payment.succeeded",
        "max_response_ms": 5000,
        "slow_response_ms": 2000,
        "replay_window_seconds": 300,
    },
    "api": {
        # Regexes matched against the request path in the merchant's API logs.
        "create_payment_path": r"/payments/?$",
        "status_check_path": r"/payments/(?P<id>[^/?]+)/?$",
        "refund_path": r"/payments/(?P<id>[^/?]+)/refunds?/?$",
        "idempotency_header": "Idempotency-Key",
        # Field names inside request/response bodies.
        "reference_field": "reference_id",
        "amount_field": "amount",
        "payment_id_field": "id",
        # "minor" means integer amounts in the smallest unit (paise, cents).
        "amount_unit": "minor",
        "max_status_polls_per_minute": 12,
        "sandbox_hosts": ["sandbox", "test", "staging", "uat"],
    },
    "flow": {
        # Scenario ids that must pass for sign-off. See flows.py for the catalogue.
        "required_scenarios": [
            "payment_success",
            "payment_failure",
            "pending_resolution",
            "customer_abandons",
            "duplicate_webhook",
            "callback_before_webhook",
            "full_refund",
            "partial_refund",
            "amount_tampering",
        ],
    },
    "code": {
        "max_files": 5000,
        "max_file_bytes": 1_000_000,
    },
}


def _merge(base: dict, override: dict) -> dict:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_profile(path: str | None = None) -> dict:
    """Return the default profile, merged with a JSON override file if given."""
    path = path or os.environ.get("SIGNOFF_PROFILE")
    if not path:
        return copy.deepcopy(DEFAULT_PROFILE)
    override = json.loads(Path(path).expanduser().read_text())
    return _merge(DEFAULT_PROFILE, override)
