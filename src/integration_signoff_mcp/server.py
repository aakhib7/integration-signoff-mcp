"""MCP server: review a merchant's payment integration and issue a go-live sign-off."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Literal

from mcp.server import MCPServer

from . import code_review, flows, log_analyzer, signoff, store, webhook_probe
from .config import load_profile
from .models import summarise

# STDIO servers must never write to stdout; logging goes to stderr.
logger = logging.getLogger(__name__)

mcp = MCPServer(
    "integration-signoff",
    version="0.1.0",
    instructions=(
        "Reviews a merchant's payment gateway integration before go-live. Start with start_review, run the four "
        "checks (probe_webhook, analyze_api_logs, record_flow_result for each scenario, review_code), or mark an "
        "area not applicable, then call generate_signoff. Blockers cannot be waived. Always tell the user the "
        "decision and the exact fixes for anything that failed."
    ),
)

Area = Literal["webhook", "api", "flow", "code"]


def _profile() -> dict:
    return load_profile()


def _area_summary(review: dict, area: str) -> dict:
    findings = store.area_findings(review, area)
    return {
        "review_id": review["review_id"],
        "area": area,
        "summary": summarise(findings),
        "failures": [
            {"check_id": f.check_id, "severity": f.severity, "title": f.title, "detail": f.detail, "fix": f.fix}
            for f in findings if f.status == "fail"
        ],
        "warnings": [{"check_id": f.check_id, "title": f.title, "detail": f.detail} for f in findings
                     if f.status == "warn"],
        "passed": [f"{f.check_id} {f.title}" for f in findings if f.status == "pass"],
    }


# ---------------------------------------------------------------- tools


@mcp.tool()
def start_review(
    merchant_name: str,
    reviewer: str = "",
    integration_type: Literal["api", "sdk", "plugin", "hosted"] = "api",
) -> dict:
    """Start a go-live review for a merchant's payment integration. Returns the review_id used by every other tool.

    Args:
        merchant_name: The merchant's business name
        reviewer: Name of the person who will sign off (shown on the report)
        integration_type: How the merchant integrates: api, sdk, plugin or hosted checkout
    """
    review = store.new_review(merchant_name, reviewer, integration_type)
    return {
        "review_id": review["review_id"],
        "next_steps": [
            "probe_webhook: test the merchant's sandbox webhook endpoint",
            "analyze_api_logs: check their sandbox API request/response logs",
            "list_flow_scenarios, then record_flow_result for each scenario they run",
            "review_code: scan their integration code",
            "mark_not_applicable for any area that does not apply, then generate_signoff",
        ],
    }


@mcp.tool()
def probe_webhook(review_id: str, url: str, signing_secret: str, allow_private: bool = False) -> dict:
    """Send signed test events (and deliberately invalid ones) to the merchant's webhook endpoint and check
    HTTPS, signature verification, replay protection, duplicate handling and response time.

    Only use the merchant's sandbox/UAT endpoint and sandbox signing secret. The secret is used to sign test
    events and is never stored.

    Args:
        review_id: From start_review
        url: The merchant's webhook endpoint URL
        signing_secret: The sandbox webhook signing secret shared with the merchant
        allow_private: Allow localhost/private-network URLs (for testing your own setup only)
    """
    review = store.load(review_id)
    findings = webhook_probe.probe(url, signing_secret, _profile(), allow_private=allow_private)
    store.record_area(review, "webhook", findings, target=url)
    store.save(review)
    return _area_summary(review, "webhook")


@mcp.tool()
def analyze_api_logs(review_id: str, log_file_path: str = "", log_text: str = "") -> dict:
    """Analyse the merchant's sandbox API request/response logs: idempotency keys, unique order references,
    retry behaviour, amount units, server-side status checks, polling rate, card data or secrets in traffic,
    and refund coverage.

    Provide either a path to a JSON/JSON Lines file or the log text itself.

    Args:
        review_id: From start_review
        log_file_path: Path to a .json or .jsonl export of API calls
        log_text: The log content, if not using a file
    """
    if not log_file_path and not log_text:
        raise ValueError("Provide log_file_path or log_text.")
    text = Path(log_file_path).expanduser().read_text() if log_file_path else log_text
    review = store.load(review_id)
    findings = log_analyzer.analyse(text, _profile())
    store.record_area(review, "api", findings, target=log_file_path or "pasted logs")
    store.save(review)
    return _area_summary(review, "api")


@mcp.tool()
def list_flow_scenarios(review_id: str) -> dict:
    """List the end-to-end scenarios the merchant must run in sandbox, with steps, expected behaviour,
    the evidence to collect, and what has been recorded so far.

    Args:
        review_id: From start_review
    """
    review = store.load(review_id)
    return {"scenarios": flows.catalogue(_profile()["flow"]["required_scenarios"], review["flow_results"])}


@mcp.tool()
def record_flow_result(review_id: str, scenario_id: str, passed: bool, evidence: str, notes: str = "") -> dict:
    """Record the outcome of one end-to-end scenario the merchant ran.

    Args:
        review_id: From start_review
        scenario_id: Id from list_flow_scenarios, e.g. payment_success
        passed: True if the merchant's system behaved as expected
        evidence: Order id, payment id, log line or screenshot reference that proves the outcome
        notes: What happened, especially if it failed
    """
    review = store.load(review_id)
    required = _profile()["flow"]["required_scenarios"]
    result = flows.record(review, scenario_id, passed, evidence, required, notes)
    store.save(review)
    remaining = [s for s in required if s not in review["flow_results"]]
    return {"scenario_id": scenario_id, **result, "required_scenarios_remaining": remaining}


@mcp.tool()
def review_code(review_id: str, path: str) -> dict:
    """Scan the merchant's integration code for hard-coded secrets, secrets in client-side code, missing webhook
    signature verification, non-constant-time comparisons, disabled TLS checks, sensitive data in logs,
    floating-point money, client-supplied amounts, plain-HTTP endpoints and trusting redirect parameters.

    Args:
        review_id: From start_review
        path: Local folder (or single file) containing the merchant's integration code
    """
    review = store.load(review_id)
    findings = code_review.review(path, _profile())
    store.record_area(review, "code", findings, target=path)
    store.save(review)
    return _area_summary(review, "code")


@mcp.tool()
def mark_not_applicable(review_id: str, area: Area, reason: str) -> dict:
    """Mark a review area as not applicable, with a reason that appears on the report
    (for example: no webhooks because the merchant uses a hosted plugin that polls).

    Args:
        review_id: From start_review
        area: webhook, api, flow or code
        reason: Why this area does not apply
    """
    review = store.load(review_id)
    store.mark_not_applicable(review, area, reason)
    store.save(review)
    return {"review_id": review_id, "area": area, "status": "not_applicable", "reason": reason}


@mcp.tool()
def waive_finding(review_id: str, check_id: str, reason: str, approved_by: str) -> dict:
    """Waive a failed major or minor finding so it no longer blocks sign-off. Blockers cannot be waived.
    The waiver, reason and approver are printed on the report.

    Args:
        review_id: From start_review
        check_id: The finding's id, e.g. A09 or W03
        reason: Why it is acceptable to go live with this issue
        approved_by: Name of the person accepting the risk
    """
    review = store.load(review_id)
    waiver = signoff.waive(review, _profile(), check_id, reason, approved_by)
    store.save(review)
    return {"check_id": check_id, **waiver}


@mcp.tool()
def review_status(review_id: str) -> dict:
    """Show where a review stands: which areas are done, the current decision, and what is blocking go-live.

    Args:
        review_id: From start_review
    """
    review = store.load(review_id)
    result = signoff.decide(review, _profile())
    return {
        "review_id": review_id,
        "merchant": review["merchant"],
        "areas": {area: review["areas"][area]["status"] for area in review["areas"]},
        "decision_if_generated_now": result["decision"],
        "reason": result["reason"],
        "blockers": [f"{f['check_id']} {f['title']}" for f in result["blockers"]],
        "unwaived_majors": result["unwaived_majors"],
        "summary": result["summary"],
    }


@mcp.tool()
def generate_signoff(review_id: str) -> dict:
    """Generate the go-live decision and the sign-off report (Markdown plus a tamper-evident JSON copy).
    A certificate id is issued only when the decision is APPROVED or APPROVED_WITH_CONDITIONS.

    Args:
        review_id: From start_review
    """
    review = store.load(review_id)
    return signoff.generate(review, _profile())


@mcp.tool()
def verify_signoff(report_json_path: str) -> dict:
    """Check that a sign-off report's JSON file has not been edited since it was generated.

    Args:
        report_json_path: Path to the .json report written by generate_signoff
    """
    return signoff.verify(report_json_path)


@mcp.tool()
def list_reviews() -> dict:
    """List all reviews stored on this machine."""
    return {"reviews": store.list_reviews()}


# ---------------------------------------------------------------- resources


@mcp.resource("signoff://scenarios", mime_type="application/json")
def scenarios_resource() -> str:
    """The catalogue of end-to-end flow scenarios and which are required."""
    return json.dumps(flows.catalogue(_profile()["flow"]["required_scenarios"], {}), indent=2)


@mcp.resource("signoff://profile", mime_type="application/json")
def profile_resource() -> str:
    """The active rules profile (headers, endpoint patterns, thresholds)."""
    return json.dumps(_profile(), indent=2)


@mcp.resource("signoff://reviews/{review_id}/report", mime_type="text/markdown")
def report_resource(review_id: str) -> str:
    """A live preview of the sign-off report for a review (not saved, not signed)."""
    review = store.load(review_id)
    result = signoff.decide(review, _profile())
    payload = {"review": review, "result": result, "generated_at": store.utc_now(), "digest": "preview",
               "signature": None, "certificate_id": "preview"}
    return signoff.render_markdown(payload)


# ---------------------------------------------------------------- prompts


@mcp.prompt()
def run_go_live_review(merchant_name: str, integration_type: str = "api") -> str:
    """Walk through a complete go-live review for a merchant, ending in a sign-off decision."""
    return (
        f"Run a go-live integration review for the merchant {merchant_name} ({integration_type} integration).\n\n"
        "1. Call start_review and keep the review_id.\n"
        "2. Ask me for the merchant's sandbox webhook URL and signing secret, then call probe_webhook.\n"
        "3. Ask me for their sandbox API log export, then call analyze_api_logs.\n"
        "4. Call list_flow_scenarios. Go through the required scenarios one at a time: tell me what the merchant "
        "should do and what evidence to collect, then record each result with record_flow_result.\n"
        "5. Ask me for the path to their integration code, then call review_code.\n"
        "6. If an area does not apply, ask me why and call mark_not_applicable.\n"
        "7. Call generate_signoff. Report the decision in one line, then list every blocker and major issue "
        "with its exact fix, written so I can forward it to the merchant's developers.\n"
        "Do not suggest waiving blockers. Only suggest a waiver for a major issue if I ask."
    )


@mcp.prompt()
def explain_findings_to_merchant(review_id: str) -> str:
    """Draft an email to the merchant's developers explaining what to fix before go-live."""
    return (
        f"Call review_status for review {review_id}. Then draft a short email to the merchant's engineering team: "
        "one line on overall status, then a numbered list of what they must fix (blockers first, then majors), "
        "each with the reason it matters and the exact change to make. End with the recommended (non-blocking) "
        "improvements in one short list. Plain, friendly and specific; no internal check ids in the email body."
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    mcp.run(transport="stdio")
