"""End-to-end: launch the MCP server over stdio and drive a review as a client."""

import asyncio
import json
import os
import sys

import pytest
from helpers import EXAMPLES, start_merchant

pytest.importorskip("mcp")

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

SERVER = StdioServerParameters(
    command=sys.executable, args=["-m", "integration_signoff_mcp"], env={**os.environ}
)


def _json(result):
    return json.loads(result.content[0].text)


async def _review(webhook_url: str) -> dict:
    async with stdio_client(SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = sorted(t.name for t in (await session.list_tools()).tools)
            started = _json(await session.call_tool("start_review", {"merchant_name": "E2E Store"}))
            rid = started["review_id"]
            hook = _json(await session.call_tool(
                "probe_webhook",
                {"review_id": rid, "url": webhook_url, "signing_secret": "demo-secret", "allow_private": True},
            ))
            logs = _json(await session.call_tool(
                "analyze_api_logs", {"review_id": rid, "log_file_path": str(EXAMPLES / "sample_logs_good.jsonl")}
            ))
            code = _json(await session.call_tool(
                "review_code", {"review_id": rid, "path": str(EXAMPLES / "merchant_code_good")}
            ))
            scenarios = _json(await session.call_tool("list_flow_scenarios", {"review_id": rid}))["scenarios"]
            for s in scenarios:
                if s["required"]:
                    await session.call_tool(
                        "record_flow_result",
                        {"review_id": rid, "scenario_id": s["scenario_id"], "passed": True, "evidence": "ORD-1"},
                    )
            final = _json(await session.call_tool("generate_signoff", {"review_id": rid}))
            prompts = sorted(p.name for p in (await session.list_prompts()).prompts)
            return {"tools": tools, "hook": hook, "logs": logs, "code": code, "final": final, "prompts": prompts}


def test_full_review_over_stdio():
    server, url = start_merchant("good")
    try:
        result = asyncio.run(_review(url))
    finally:
        server.shutdown()
    assert "generate_signoff" in result["tools"] and "probe_webhook" in result["tools"]
    assert result["hook"]["failures"] == []
    assert result["logs"]["failures"] == []
    assert result["code"]["failures"] == []
    assert result["final"]["decision"] == "APPROVED"
    assert result["prompts"] == ["explain_findings_to_merchant", "run_go_live_review"]
