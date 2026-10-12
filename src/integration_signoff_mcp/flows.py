"""Guided end-to-end flow scenarios.

Each scenario is run by the merchant in sandbox. The reviewer records whether
the merchant's system behaved as expected, with evidence (order id, payment id,
screenshot reference or log line). Required scenarios come from the profile.
"""

from __future__ import annotations

from .models import Finding
from .store import utc_now

AREA = "flow"

SCENARIOS: dict[str, dict] = {
    "payment_success": {
        "title": "Successful payment",
        "steps": "Place an order and pay with a sandbox success method.",
        "expected": "Order is marked paid only after the webhook or a server-side status check confirms success. "
        "Customer sees a confirmation page.",
        "evidence": "Order id, payment id, and the log line showing the status confirmation.",
        "severity": "blocker",
    },
    "payment_failure": {
        "title": "Failed payment",
        "steps": "Pay with a sandbox method that declines.",
        "expected": "Order stays unpaid, the customer sees a clear failure message and can retry with a new attempt.",
        "evidence": "Order id, payment id, screenshot of the failure page.",
        "severity": "blocker",
    },
    "pending_resolution": {
        "title": "Pending payment resolves later",
        "steps": "Use a sandbox method that stays pending, then let it succeed or fail.",
        "expected": "Order shows a pending state; it is updated by webhook or polling when the final status arrives, "
        "without manual action.",
        "evidence": "Order timeline showing pending then final state.",
        "severity": "blocker",
    },
    "customer_abandons": {
        "title": "Customer closes the payment page",
        "steps": "Start a payment and close the browser or app before completing it.",
        "expected": "Order is not marked paid; it expires or is cancelled after the gateway's expiry time.",
        "evidence": "Order id and its final state.",
        "severity": "major",
    },
    "duplicate_webhook": {
        "title": "Same webhook delivered twice",
        "steps": "Resend a success webhook from the gateway dashboard (or use the webhook probe).",
        "expected": "Second delivery is acknowledged with 2xx; the order is fulfilled once, no duplicate email, "
        "stock or wallet credit.",
        "evidence": "Event id and the merchant log showing the duplicate was skipped.",
        "severity": "blocker",
    },
    "callback_before_webhook": {
        "title": "Customer returns before the webhook arrives",
        "steps": "Complete a payment with webhooks paused or delayed, so the browser redirect arrives first.",
        "expected": "Merchant checks status server-to-server on redirect; it does not trust redirect query parameters "
        "to mark the order paid.",
        "evidence": "Log line of the status check made on redirect.",
        "severity": "blocker",
    },
    "full_refund": {
        "title": "Full refund",
        "steps": "Refund a successful sandbox payment in full from the merchant's system.",
        "expected": "Refund is created with an idempotency key, the order shows refunded, and the refund webhook "
        "updates the final refund status.",
        "evidence": "Refund id and order state.",
        "severity": "major",
    },
    "partial_refund": {
        "title": "Partial refund",
        "steps": "Refund part of a successful payment, then try to refund more than the remaining amount.",
        "expected": "Partial refund succeeds; the over-refund is blocked by the merchant or rejected cleanly by the "
        "gateway, with a clear message.",
        "evidence": "Refund ids and the error shown for the over-refund.",
        "severity": "major",
    },
    "amount_tampering": {
        "title": "Amount changed in the browser",
        "steps": "Modify the amount in the browser (devtools or proxy) before the payment is created.",
        "expected": "Amount is set on the server from the order; the tampered value is ignored or the payment is "
        "rejected.",
        "evidence": "Order amount vs payment amount.",
        "severity": "blocker",
    },
    "webhook_signature_rotation": {
        "title": "Webhook secret rotation",
        "steps": "Rotate the webhook secret in the gateway dashboard and send a test event.",
        "expected": "Merchant can update the secret from configuration without a code release; events keep verifying.",
        "evidence": "Config change record and a verified event after rotation.",
        "severity": "minor",
    },
    "settlement_reconciliation": {
        "title": "Settlement reconciliation",
        "steps": "Download the sandbox settlement report and match it with the merchant's orders.",
        "expected": "Every paid order maps to a settlement line by reference; fees and refunds are accounted for.",
        "evidence": "Reconciliation output or sheet.",
        "severity": "minor",
    },
}


def catalogue(required: list[str], results: dict) -> list[dict]:
    """All scenarios with whether they are required and their recorded result."""
    rows = []
    for scenario_id, scenario in SCENARIOS.items():
        result = results.get(scenario_id)
        rows.append(
            {
                "scenario_id": scenario_id,
                **{k: scenario[k] for k in ("title", "steps", "expected", "evidence", "severity")},
                "required": scenario_id in required,
                "result": result["outcome"] if result else "not_run",
            }
        )
    return rows


def record(
    review: dict, scenario_id: str, passed: bool, evidence: str, required: list[str], notes: str = ""
) -> dict:
    if scenario_id not in SCENARIOS:
        raise ValueError(f"Unknown scenario '{scenario_id}'. Known: {', '.join(SCENARIOS)}")
    if not evidence.strip():
        raise ValueError("Evidence is required: an order id, payment id, log line or screenshot reference.")
    result = {
        "outcome": "pass" if passed else "fail",
        "evidence": evidence.strip(),
        "notes": notes.strip(),
        "recorded_at": utc_now(),
    }
    review["flow_results"][scenario_id] = result
    review["areas"]["flow"]["status"] = "run"
    review["areas"]["flow"]["findings"] = [f.to_dict() for f in findings(review, required)]
    return result


def findings(review: dict, required: list[str]) -> list[Finding]:
    results = review["flow_results"]
    out: list[Finding] = []
    for scenario_id, scenario in SCENARIOS.items():
        result = results.get(scenario_id)
        is_required = scenario_id in required
        if result is None:
            if is_required:
                out.append(
                    Finding(
                        f"F-{scenario_id}", AREA, scenario["severity"], "fail", scenario["title"],
                        "Required scenario has not been run.", f"Run it: {scenario['steps']}",
                    )
                )
            continue
        passed = result["outcome"] == "pass"
        out.append(
            Finding(
                f"F-{scenario_id}", AREA, scenario["severity"] if is_required else "minor",
                "pass" if passed else "fail", scenario["title"],
                (result["notes"] or ("Behaved as expected." if passed else "Did not behave as expected.")),
                "" if passed else f"Expected: {scenario['expected']}",
                {"evidence": result["evidence"], "recorded_at": result["recorded_at"]},
            )
        )
    return out
