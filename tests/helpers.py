"""Shared test setup: isolated data dir, paths to the bundled examples."""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"

os.environ["SIGNOFF_DATA_DIR"] = tempfile.mkdtemp(prefix="signoff-tests-")
os.environ.pop("SIGNOFF_PROFILE", None)
sys.path.insert(0, str(EXAMPLES))

import demo_webhook_server  # noqa: E402

from integration_signoff_mcp.config import load_profile  # noqa: E402

PROFILE = load_profile()


def statuses(findings):
    return {f.check_id: f.status for f in findings}


def read_example(name: str) -> str:
    return (EXAMPLES / name).read_text()


_next_port = [28765]


def start_merchant(mode: str):
    """Start the demo merchant webhook server; returns (server, url)."""
    _next_port[0] += 1
    port = _next_port[0]
    server = demo_webhook_server.serve(mode, port)
    return server, f"http://127.0.0.1:{port}/webhook"
