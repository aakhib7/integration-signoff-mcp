import tempfile
from pathlib import Path

from helpers import EXAMPLES, PROFILE, statuses

from integration_signoff_mcp import code_review


def test_problem_code_is_caught():
    result = statuses(code_review.review(str(EXAMPLES / "merchant_code_bad"), PROFILE))
    assert result["C01"] == "fail"  # hard-coded secret
    assert result["C02"] == "fail"  # secret in client-side code
    assert result["C03"] == "fail"  # webhook without signature check
    assert result["C05"] == "fail"  # verify=False
    assert result["C06"] == "warn"  # card number logged
    assert result["C07"] == "warn"  # float(amount)
    assert result["C08"] == "warn"  # amount from request
    assert result["C09"] == "fail"  # http:// gateway URL
    assert result["C10"] == "warn"  # trusts ?status=success


def test_clean_code_passes():
    result = statuses(code_review.review(str(EXAMPLES / "merchant_code_good"), PROFILE))
    assert {k: v for k, v in result.items() if v != "pass"} == {}


def test_secret_values_are_masked():
    finding = {f.check_id: f for f in code_review.review(str(EXAMPLES / "merchant_code_bad"), PROFILE)}["C01"]
    assert "fakeSecret9f8a7b6c5d4e3f2a" not in finding.detail


def test_plain_signature_comparison_is_flagged():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "hook.js").write_text(
            "function webhook(req) {\n"
            "  const sig = createHmac('sha256', s).update(req.body).digest('hex');\n"
            "  if (sig === req.headers['x-signature']) { ok(); }\n"
            "}\n"
        )
        result = statuses(code_review.review(tmp, PROFILE))
    assert result["C03"] == "pass"
    assert result["C04"] == "warn"


def test_dependency_folders_are_skipped():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "node_modules", "lib").mkdir(parents=True)
        Path(tmp, "node_modules", "lib", "x.js").write_text('const api_secret = "abcdefghijklmnop1234";')
        result = statuses(code_review.review(tmp, PROFILE))
    assert result["C01"] == "pass"


def test_placeholders_are_not_reported_as_secrets():
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "settings.py").write_text('API_KEY = "your-api-key-here-please"\n')
        result = statuses(code_review.review(tmp, PROFILE))
    assert result["C01"] == "pass"
