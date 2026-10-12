# Integration Sign-off MCP

An [MCP](https://modelcontextprotocol.io) server that reviews a merchant's payment gateway integration before
go-live and issues a sign-off report.

It checks four areas, applies clear decision rules, and produces a Markdown report with a tamper-evident JSON
copy. Use it from Claude Desktop, Claude Code or any MCP client: ask *"Run a go-live review for Acme Travel"*
and the assistant walks through the checks, records evidence and tells you what the merchant must fix.

It is gateway-agnostic. Header names, signing scheme, endpoint paths and field names come from a profile you
can override.

## What it checks

| Area | How | Examples of what it catches |
| --- | --- | --- |
| **Webhook endpoint** | Sends signed test events, and deliberately bad ones, to the merchant's sandbox endpoint | Accepts unsigned or wrongly signed events, no replay protection, slow responses, crashes on bad input, fails on duplicate deliveries |
| **API usage** | Analyses the merchant's sandbox API request/response logs (JSON or JSON Lines) | Missing idempotency keys, retries that create a second charge, reused order references, amounts in rupees instead of paise, no server-side status check, aggressive polling, card numbers or CVVs in traffic |
| **End-to-end flows** | Guided scenarios the merchant runs in sandbox; each result needs evidence | Success, failure, pending, abandoned checkout, duplicate webhook, redirect before webhook, full and partial refunds, amount tampering |
| **Code** | Pattern-based scan of the merchant's integration code | Hard-coded secrets, secrets in browser or app code, webhook handler without signature verification, `==` signature comparison, `verify=False`, logging card data, float money, amount taken from the request, trusting `?status=success` |

Every check returns `pass`, `fail`, `warn` or `skipped`, a severity, the detail it observed, and the exact fix.

## Decision rules

| Decision | When |
| --- | --- |
| `INCOMPLETE` | An area was neither checked nor marked not applicable |
| `NOT_APPROVED` | Any **blocker** failed. Blockers cannot be waived |
| `CHANGES_REQUIRED` | A **major** issue failed and has no waiver |
| `APPROVED_WITH_CONDITIONS` | Every failed major issue has a recorded waiver (reason and approver) |
| `APPROVED` | No blocker or major failures |

Warnings and minor issues never block; they appear as recommendations. A certificate id is issued only for the
two approved decisions.

Each report is saved as Markdown and JSON. The JSON includes a SHA-256 digest of its contents and, if
`SIGNOFF_SIGNING_KEY` is set, an HMAC signature. `verify_signoff` detects any later edit.

## Tools, resources and prompts

| Type | Name | Purpose |
| --- | --- | --- |
| Tool | `start_review` | Create a review for a merchant; returns the `review_id` |
| Tool | `probe_webhook` | Run the webhook checks against a URL with the sandbox signing secret (never stored) |
| Tool | `analyze_api_logs` | Run the API checks on a log file or pasted logs |
| Tool | `list_flow_scenarios` | Show scenarios with steps, expected behaviour and evidence to collect |
| Tool | `record_flow_result` | Record one scenario's outcome with evidence |
| Tool | `review_code` | Scan a local folder of integration code |
| Tool | `mark_not_applicable` | Exclude an area, with a reason printed on the report |
| Tool | `waive_finding` | Accept a failed major or minor issue, with reason and approver |
| Tool | `review_status` | Current state and what is blocking go-live |
| Tool | `generate_signoff` | Decide and write the report |
| Tool | `verify_signoff` | Check a report has not been edited |
| Tool | `list_reviews` | Reviews stored on this machine |
| Resource | `signoff://scenarios` | Scenario catalogue |
| Resource | `signoff://profile` | Active rules profile |
| Resource | `signoff://reviews/{review_id}/report` | Live report preview |
| Prompt | `run_go_live_review` | Guided end-to-end review |
| Prompt | `explain_findings_to_merchant` | Draft the fix-list email to the merchant's developers |

## Install and run

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/<your-username>/integration-signoff-mcp.git
cd integration-signoff-mcp
uv sync
uv run pytest                      # unit tests + an end-to-end MCP test over stdio
uv run integration-signoff-mcp     # start the server on stdio
```

### Connect to Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` and restart Claude Desktop:

```json
{
  "mcpServers": {
    "integration-signoff": {
      "command": "uv",
      "args": ["--directory", "/ABSOLUTE/PATH/TO/integration-signoff-mcp", "run", "integration-signoff-mcp"],
      "env": { "SIGNOFF_SIGNING_KEY": "choose-a-long-random-string" }
    }
  }
}
```

### Connect to Claude Code

```bash
claude mcp add integration-signoff -- uv --directory /ABSOLUTE/PATH/TO/integration-signoff-mcp run integration-signoff-mcp
```

## Try it in five minutes

The `examples/` folder has a demo merchant webhook, sample logs and sample code, each in a good and a bad version.

```bash
python examples/demo_webhook_server.py --mode bad
```

Then ask your MCP client:

> Run a go-live review for Demo Store. Webhook URL is http://127.0.0.1:8765/webhook with secret demo-secret
> (allow private addresses). Logs are in examples/sample_logs_bad.jsonl and code is in examples/merchant_code_bad.

Switch to `--mode good`, `sample_logs_good.jsonl` and `merchant_code_good` to see an approval.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SIGNOFF_PROFILE` | built-in generic profile | Path to a JSON file overriding any profile keys |
| `SIGNOFF_DATA_DIR` | `~/.integration-signoff` | Where reviews and reports are stored |
| `SIGNOFF_SIGNING_KEY` | unset | Signs reports with HMAC-SHA256 so they can be verified |

The default profile expects webhooks signed as hex HMAC-SHA256 of `{timestamp}.{body}` in `X-Signature`, an
`Idempotency-Key` header, `/payments` endpoints and integer amounts in minor units. See
[`examples/profile.example.json`](examples/profile.example.json) for a gateway that signs differently, and
[`config.py`](src/integration_signoff_mcp/config.py) for every key.

### API log format

One object per API call, as a JSON array or JSON Lines:

```json
{"timestamp": "2026-10-01T10:00:00Z", "method": "POST", "url": "https://api.sandbox.examplepay.com/v1/payments",
 "status": 201, "request_headers": {"Idempotency-Key": "k-1001"},
 "request_body": {"reference_id": "ORD-1001", "amount": 49900, "currency": "INR"},
 "response_body": {"id": "pay_A1", "status": "created"}}
```

Use `"status": null` for a call that timed out. Redact credentials before exporting; the tool warns if it sees them.

## Safety notes

- Run `probe_webhook` against **sandbox endpoints only**. The valid test events are well formed, and a handler
  that does not check the `test` flag may act on them.
- Private and loopback addresses are refused unless `allow_private` is set, so the tool cannot be pointed at
  internal services by accident.
- Signing secrets are used in memory and never written to disk. Card numbers and secrets found in logs or code
  are masked in reports.
- The code review is pattern-based. Results marked `warn` are prompts for a human to look, not proof of a bug.
  Automated checks support a reviewer's judgement; they do not replace it.

## Project layout

```
src/integration_signoff_mcp/
  server.py          MCP tools, resources and prompts
  webhook_probe.py   active webhook checks
  log_analyzer.py    API log checks
  flows.py           end-to-end scenario catalogue
  code_review.py     static code checks
  signoff.py         decision rules, report, signing and verification
  store.py           review state (JSON files)
  config.py          gateway-agnostic profile
examples/            demo webhook server, sample logs, sample merchant code
tests/               pytest suite, including an end-to-end MCP test
```

## License

MIT
