import json

from helpers import PROFILE, read_example, statuses

from integration_signoff_mcp import log_analyzer


def test_clean_logs_pass():
    result = statuses(log_analyzer.analyse(read_example("sample_logs_good.jsonl"), PROFILE))
    assert set(result.values()) == {"pass"}


def test_problem_logs_are_caught():
    findings = {f.check_id: f for f in log_analyzer.analyse(read_example("sample_logs_bad.jsonl"), PROFILE)}
    assert findings["A04"].status == "fail"  # missing idempotency key
    assert findings["A05"].status == "fail" and findings["A05"].severity == "blocker"  # reference reused
    assert findings["A06"].status == "fail"  # retry after timeout used a new key
    assert findings["A07"].status == "fail"  # 499.0 instead of 49900
    assert findings["A08"].status == "fail"  # pay_B2 never status-checked
    assert findings["A09"].status == "warn"  # polling too fast
    assert findings["A11"].status == "fail"  # card number and CVV in traffic
    assert findings["A12"].status == "warn"  # Authorization header in export
    assert findings["A13"].status == "warn"  # no refunds tested


def test_card_numbers_are_masked_in_output():
    detail = {f.check_id: f for f in log_analyzer.analyse(read_example("sample_logs_bad.jsonl"), PROFILE)}["A11"]
    assert "4111 1111 1111 1111" not in detail.detail
    assert "4111********1111" in detail.detail


def test_json_array_input_is_accepted():
    lines = read_example("sample_logs_good.jsonl").splitlines()
    as_array = json.dumps([json.loads(line) for line in lines])
    assert statuses(log_analyzer.analyse(as_array, PROFILE)) == statuses(
        log_analyzer.analyse("\n".join(lines), PROFILE)
    )


def test_logs_without_creates_report_a_clear_problem():
    findings = log_analyzer.analyse('{"method": "GET", "url": "/health", "status": 200}', PROFILE)
    assert findings[-1].check_id == "A02"
    assert findings[-1].status == "fail"


def test_luhn():
    assert log_analyzer._luhn("4111111111111111")
    assert not log_analyzer._luhn("4111111111111112")
