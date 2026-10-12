import json
import os

import pytest
from helpers import EXAMPLES, PROFILE, read_example, start_merchant

from integration_signoff_mcp import code_review, flows, log_analyzer, signoff, store, webhook_probe


def _complete_clean_review():
    review = store.new_review("Acme Travel", reviewer="Aakhib", integration_type="api")
    server, url = start_merchant("good")
    try:
        store.record_area(review, "webhook", webhook_probe.probe(url, "demo-secret", PROFILE, allow_private=True), url)
    finally:
        server.shutdown()
    store.record_area(review, "api", log_analyzer.analyse(read_example("sample_logs_good.jsonl"), PROFILE))
    store.record_area(review, "code", code_review.review(str(EXAMPLES / "merchant_code_good"), PROFILE))
    required = PROFILE["flow"]["required_scenarios"]
    for scenario in required:
        flows.record(review, scenario, True, f"order ORD-{scenario}", required)
    store.save(review)
    return review


def test_clean_review_is_approved_with_certificate():
    review = _complete_clean_review()
    result = signoff.generate(review, PROFILE)
    assert result["decision"] == "APPROVED"
    assert result["certificate_id"].startswith("SO-")
    assert "cleared for go-live" in result["markdown"]
    assert signoff.verify(result["report_json_path"])["valid"] is True


def test_editing_the_report_breaks_verification():
    review = _complete_clean_review()
    path = signoff.generate(review, PROFILE)["report_json_path"]
    data = json.loads(open(path).read())
    data["review"]["merchant"] = "Someone Else"
    open(path, "w").write(json.dumps(data))
    assert signoff.verify(path)["valid"] is False


def test_signing_key_signs_and_verifies():
    os.environ["SIGNOFF_SIGNING_KEY"] = "test-key"
    try:
        review = _complete_clean_review()
        result = signoff.generate(review, PROFILE)
        check = signoff.verify(result["report_json_path"])
        assert check["signature_valid"] is True
        os.environ["SIGNOFF_SIGNING_KEY"] = "other-key"
        assert signoff.verify(result["report_json_path"])["valid"] is False
    finally:
        os.environ.pop("SIGNOFF_SIGNING_KEY", None)


def test_unchecked_areas_make_the_review_incomplete():
    review = store.new_review("Half Done")
    store.record_area(review, "code", code_review.review(str(EXAMPLES / "merchant_code_good"), PROFILE))
    assert signoff.decide(review, PROFILE)["decision"] == "INCOMPLETE"


def test_not_applicable_areas_count_as_covered():
    review = _complete_clean_review()
    store.mark_not_applicable(review, "code", "Hosted plugin, no custom code")
    result = signoff.generate(review, PROFILE)
    assert result["decision"] == "APPROVED"
    assert "Hosted plugin, no custom code" in result["markdown"]


def test_blockers_stop_sign_off_and_cannot_be_waived():
    review = _complete_clean_review()
    store.record_area(review, "code", code_review.review(str(EXAMPLES / "merchant_code_bad"), PROFILE))
    result = signoff.generate(review, PROFILE)
    assert result["decision"] == "NOT_APPROVED"
    assert result["certificate_id"] is None
    with pytest.raises(ValueError):
        signoff.waive(review, PROFILE, "C01", "accepted", "Someone")


def test_major_issue_can_be_waived_for_conditional_approval():
    review = _complete_clean_review()
    required = PROFILE["flow"]["required_scenarios"]
    flows.record(review, "partial_refund", False, "refund rfnd_9", required, notes="Over-refund not blocked")
    assert signoff.decide(review, PROFILE)["decision"] == "CHANGES_REQUIRED"
    signoff.waive(review, PROFILE, "F-partial_refund", "Partial refunds disabled at launch", "Risk team")
    result = signoff.generate(review, PROFILE)
    assert result["decision"] == "APPROVED_WITH_CONDITIONS"
    assert "Partial refunds disabled at launch" in result["markdown"]


def test_missing_required_scenario_blocks():
    review = _complete_clean_review()
    del review["flow_results"]["payment_success"]
    assert signoff.decide(review, PROFILE)["decision"] == "NOT_APPROVED"


def test_flow_evidence_is_required():
    review = store.new_review("Evidence Co")
    with pytest.raises(ValueError):
        flows.record(review, "payment_success", True, "  ", PROFILE["flow"]["required_scenarios"])


def test_review_ids_cannot_escape_the_data_dir():
    with pytest.raises(ValueError):
        store.load("../../etc/passwd")
