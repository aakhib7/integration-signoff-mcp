"""Turns a review's findings into a go-live decision and a sign-off report.

Decision rules, applied in order:

1. INCOMPLETE         an area was neither run nor marked not applicable
2. NOT_APPROVED       any blocker failed (blockers cannot be waived)
3. CHANGES_REQUIRED   any major failed without a recorded waiver
4. APPROVED_WITH_CONDITIONS   every failed major has a waiver
5. APPROVED           no blocker or major failures

Warnings and minor failures never block; they are listed as recommendations.

Each report has a JSON twin with a SHA-256 digest of its contents. If the
SIGNOFF_SIGNING_KEY environment variable is set, the digest is also signed with
HMAC-SHA256, so verify_signoff can prove the report was not edited.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

from . import flows
from .models import AREAS, Finding, summarise
from .store import data_dir, utc_now

APPROVED_DECISIONS = ("APPROVED", "APPROVED_WITH_CONDITIONS")
AREA_TITLES = {"webhook": "Webhook endpoint", "api": "API usage (logs)", "flow": "End-to-end flows",
               "code": "Code review"}


def collect(review: dict, profile: dict) -> list[Finding]:
    findings: list[Finding] = []
    required = profile["flow"]["required_scenarios"]
    for area in AREAS:
        state = review["areas"][area]
        if state["status"] == "not_applicable":
            continue
        if area == "flow":
            if state["status"] == "run" or review["flow_results"]:
                findings += flows.findings(review, required)
        else:
            findings += [Finding.from_dict(item) for item in state["findings"]]
    return findings


def decide(review: dict, profile: dict) -> dict:
    findings = collect(review, profile)
    waivers = review.get("waivers", {})
    missing_areas = [a for a in AREAS if review["areas"][a]["status"] == "not_run" and
                     not (a == "flow" and review["flow_results"])]
    failed_blockers = [f for f in findings if f.is_failure and f.severity == "blocker"]
    failed_majors = [f for f in findings if f.is_failure and f.severity == "major"]
    unwaived = [f for f in failed_majors if f.check_id not in waivers]
    recommendations = [f for f in findings if f.status == "warn" or (f.is_failure and f.severity == "minor")]

    if missing_areas:
        decision = "INCOMPLETE"
        reason = f"Not yet checked: {', '.join(AREA_TITLES[a] for a in missing_areas)}."
    elif failed_blockers:
        decision = "NOT_APPROVED"
        reason = f"{len(failed_blockers)} blocker(s) must be fixed before go-live."
    elif unwaived:
        decision = "CHANGES_REQUIRED"
        reason = f"{len(unwaived)} major issue(s) must be fixed or waived by the reviewer."
    elif failed_majors:
        decision = "APPROVED_WITH_CONDITIONS"
        reason = f"Approved with {len(failed_majors)} waived major issue(s)."
    else:
        decision = "APPROVED"
        reason = "No blocker or major issues."

    return {
        "decision": decision,
        "reason": reason,
        "missing_areas": missing_areas,
        "blockers": [f.to_dict() for f in failed_blockers],
        "majors": [f.to_dict() for f in failed_majors],
        "unwaived_majors": [f.check_id for f in unwaived],
        "recommendations": [f.to_dict() for f in recommendations],
        "summary": summarise(findings),
        "findings": [f.to_dict() for f in findings],
    }


def waive(review: dict, profile: dict, check_id: str, reason: str, by: str) -> dict:
    findings = {f.check_id: f for f in collect(review, profile)}
    finding = findings.get(check_id)
    if finding is None:
        raise ValueError(f"No finding with id {check_id} in this review.")
    if not finding.is_failure:
        raise ValueError(f"{check_id} did not fail; nothing to waive.")
    if finding.severity == "blocker":
        raise ValueError(f"{check_id} is a blocker. Blockers cannot be waived; they must be fixed.")
    if not reason.strip() or not by.strip():
        raise ValueError("A waiver needs a reason and the name of the person approving it.")
    waiver = {"reason": reason.strip(), "by": by.strip(), "at": utc_now()}
    review.setdefault("waivers", {})[check_id] = waiver
    return waiver


# ---------------------------------------------------------------- report


def _digest(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _signature(digest: str) -> str | None:
    key = os.environ.get("SIGNOFF_SIGNING_KEY")
    if not key:
        return None
    return hmac.new(key.encode(), digest.encode(), hashlib.sha256).hexdigest()


def _status_icon(finding: dict, waivers: dict) -> str:
    if finding["status"] == "fail" and finding["check_id"] in waivers:
        return "WAIVED"
    return {"pass": "PASS", "fail": "FAIL", "warn": "WARN", "skipped": "SKIP"}[finding["status"]]


def render_markdown(payload: dict) -> str:
    review, result = payload["review"], payload["result"]
    waivers = review.get("waivers", {})
    approved = result["decision"] in APPROVED_DECISIONS
    counts = result["summary"]["by_status"]
    lines = [
        f"# Integration sign-off: {review['merchant']}",
        "",
        f"**Decision: {result['decision'].replace('_', ' ')}**. {result['reason']}",
        "",
        "| | |",
        "| --- | --- |",
        f"| Review id | `{review['review_id']}` |",
        f"| Integration type | {review.get('integration_type', '')} |",
        f"| Reviewer | {review.get('reviewer') or 'not recorded'} |",
        f"| Generated | {payload['generated_at']} |",
        f"| Checks | {result['summary']['total']} total: {counts['pass']} pass, {counts['fail']} fail, "
        f"{counts['warn']} warn, {counts['skipped']} skipped |",
        "",
    ]

    if result["blockers"] or result["unwaived_majors"]:
        lines += ["## Must fix before go-live", ""]
        for finding in result["blockers"] + [f for f in result["majors"] if f["check_id"] in result["unwaived_majors"]]:
            lines.append(f"- **{finding['check_id']} {finding['title']}** ({finding['severity']}). {finding['fix']}")
        lines.append("")

    for area in AREAS:
        state = review["areas"][area]
        lines += [f"## {AREA_TITLES[area]}", ""]
        if state["status"] == "not_applicable":
            lines += [f"Not applicable: {state.get('reason', '')}", ""]
            continue
        area_findings = [f for f in result["findings"] if f["area"] == area]
        if not area_findings:
            lines += ["Not checked.", ""]
            continue
        if state.get("target"):
            lines += [f"Target: `{state['target']}`", ""]
        lines += ["| Result | Check | Severity | Detail |", "| --- | --- | --- | --- |"]
        for finding in area_findings:
            detail = finding["detail"].replace("\n", "<br>").replace("|", "\\|")
            if finding["fix"]:
                detail += f"<br>**Fix:** {finding['fix']}"
            if finding["evidence"].get("evidence"):
                detail += f"<br>**Evidence:** {finding['evidence']['evidence']}"
            lines.append(f"| {_status_icon(finding, waivers)} | {finding['check_id']} {finding['title']} | "
                         f"{finding['severity']} | {detail} |")
        lines.append("")

    if waivers:
        lines += ["## Waivers", ""]
        for check_id, waiver in waivers.items():
            lines.append(f"- **{check_id}**: {waiver['reason']} (approved by {waiver['by']}, {waiver['at']})")
        lines.append("")

    lines += ["## Sign-off", ""]
    if approved:
        lines += [
            f"This integration is **cleared for go-live** as of {payload['generated_at']}.",
            "",
            f"- Certificate id: `{payload['certificate_id']}`",
            f"- Report digest (SHA-256): `{payload['digest']}`",
            f"- Signature: `{payload['signature']}`" if payload["signature"] else
            "- Signature: not signed (set SIGNOFF_SIGNING_KEY to sign reports)",
            f"- Signed off by: {review.get('reviewer') or '________________'}",
        ]
    else:
        lines += ["Not signed off. Fix the items above, re-run the affected checks and generate a new report."]
    lines += ["", "_Generated by integration-signoff-mcp. Automated checks support, but do not replace, a "
                  "reviewer's judgement._", ""]
    return "\n".join(lines)


def generate(review: dict, profile: dict) -> dict:
    result = decide(review, profile)
    generated_at = utc_now()
    review_snapshot = {k: v for k, v in review.items()}
    body = {"review": review_snapshot, "result": result, "generated_at": generated_at}
    digest = _digest(body)
    payload = {
        **body,
        "digest": digest,
        "signature": _signature(digest),
        "certificate_id": f"SO-{generated_at[:10].replace('-', '')}-{digest[:10].upper()}"
        if result["decision"] in APPROVED_DECISIONS else None,
    }
    reports = data_dir() / "reports"
    reports.mkdir(exist_ok=True)
    stem = f"{review['review_id']}-{generated_at.replace(':', '').replace('+0000', 'Z')}"
    markdown = render_markdown(payload)
    md_path = reports / f"{stem}.md"
    json_path = reports / f"{stem}.json"
    md_path.write_text(markdown)
    json_path.write_text(json.dumps(payload, indent=2))
    return {
        "decision": result["decision"],
        "reason": result["reason"],
        "certificate_id": payload["certificate_id"],
        "report_markdown_path": str(md_path),
        "report_json_path": str(json_path),
        "markdown": markdown,
    }


def verify(json_path: str) -> dict:
    payload = json.loads(Path(json_path).expanduser().read_text())
    body = {k: payload[k] for k in ("review", "result", "generated_at")}
    digest = _digest(body)
    digest_ok = hmac.compare_digest(digest, payload.get("digest", ""))
    signature = payload.get("signature")
    if signature is None:
        signature_ok = None
        note = "Report is unsigned; only the digest was checked."
    elif not os.environ.get("SIGNOFF_SIGNING_KEY"):
        signature_ok = None
        note = "Report is signed, but SIGNOFF_SIGNING_KEY is not set here, so the signature cannot be checked."
    else:
        signature_ok = hmac.compare_digest(_signature(digest) or "", signature)
        note = "Signature checked with SIGNOFF_SIGNING_KEY."
    return {
        "valid": digest_ok and signature_ok is not False,
        "digest_matches": digest_ok,
        "signature_valid": signature_ok,
        "decision": payload["result"]["decision"],
        "certificate_id": payload.get("certificate_id"),
        "merchant": payload["review"]["merchant"],
        "note": note,
    }
