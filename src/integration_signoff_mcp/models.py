"""Shared data types: a finding is one checked rule with its outcome."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

AREAS = ("webhook", "api", "flow", "code")

# Severity says how much a failure matters for go-live.
#   blocker: must be fixed before go-live, cannot be waived
#   major:   must be fixed or explicitly waived by the reviewer
#   minor:   should be fixed; does not block sign-off
#   info:    context only
SEVERITIES = ("blocker", "major", "minor", "info")

# Status is the outcome of the check itself.
STATUSES = ("pass", "fail", "warn", "skipped")


@dataclass
class Finding:
    check_id: str
    area: str
    severity: str
    status: str
    title: str
    detail: str = ""
    fix: str = ""
    evidence: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.area not in AREAS:
            raise ValueError(f"area must be one of {AREAS}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        if self.status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")

    @property
    def is_failure(self) -> bool:
        return self.status == "fail"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls(**data)


def summarise(findings: list[Finding]) -> dict:
    """Count findings by status and list failures by severity."""
    counts = {status: 0 for status in STATUSES}
    failures = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.status] += 1
        if finding.is_failure:
            failures[finding.severity] += 1
    return {"total": len(findings), "by_status": counts, "failures_by_severity": failures}
