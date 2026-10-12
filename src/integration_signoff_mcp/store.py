"""Review state, kept as one JSON file per review.

Files live in SIGNOFF_DATA_DIR (default ~/.integration-signoff). Secrets passed
to the tools, such as webhook signing secrets, are never written here.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .models import AREAS, Finding

REVIEW_ID_PATTERN = re.compile(r"^[a-z0-9-]{1,80}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def data_dir() -> Path:
    path = Path(os.environ.get("SIGNOFF_DATA_DIR", "~/.integration-signoff")).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:40] or "merchant"


def _path(review_id: str) -> Path:
    if not REVIEW_ID_PATTERN.match(review_id):
        raise ValueError("Invalid review_id.")
    return data_dir() / f"{review_id}.json"


def new_review(merchant: str, reviewer: str = "", integration_type: str = "api") -> dict:
    review_id = f"{_slug(merchant)}-{uuid.uuid4().hex[:8]}"
    review = {
        "review_id": review_id,
        "merchant": merchant,
        "reviewer": reviewer,
        "integration_type": integration_type,
        "created_at": utc_now(),
        "areas": {area: {"status": "not_run", "findings": []} for area in AREAS},
        "flow_results": {},
        "waivers": {},
    }
    save(review)
    return review


def load(review_id: str) -> dict:
    path = _path(review_id)
    if not path.exists():
        raise KeyError(f"No review with id {review_id}. Start one with start_review.")
    return json.loads(path.read_text())


def save(review: dict) -> None:
    path = _path(review["review_id"])
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(review, indent=2))
    tmp.replace(path)


def record_area(review: dict, area: str, findings: list[Finding], target: str = "") -> None:
    """Replace an area's findings with a fresh run."""
    review["areas"][area] = {
        "status": "run",
        "ran_at": utc_now(),
        "target": target,
        "findings": [finding.to_dict() for finding in findings],
    }


def mark_not_applicable(review: dict, area: str, reason: str) -> None:
    if area not in AREAS:
        raise ValueError(f"area must be one of {AREAS}")
    if not reason.strip():
        raise ValueError("A reason is required to mark an area not applicable.")
    review["areas"][area] = {"status": "not_applicable", "reason": reason.strip(), "findings": []}


def area_findings(review: dict, area: str) -> list[Finding]:
    return [Finding.from_dict(item) for item in review["areas"][area]["findings"]]


def list_reviews() -> list[dict]:
    reviews = []
    for path in sorted(data_dir().glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        reviews.append(
            {"review_id": data.get("review_id"), "merchant": data.get("merchant"), "created_at": data.get("created_at")}
        )
    return reviews
