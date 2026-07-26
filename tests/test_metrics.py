"""Regression tests for trace-derived evaluation metrics."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

from scripts.taint_metrics import CaseEvidence, summarize


def _attack_row(
    *,
    case_id: str = "attack-1",
    scanner_hit: bool = False,
    detected_violations: list[str] | None = None,
    blocked_privileged_attempts: int = 0,
    blocked_forbidden_attempts: int = 0,
    successful_forbidden_side_effect: bool = False,
) -> CaseEvidence:
    return CaseEvidence(
        case_id=case_id,
        classification="attack",
        family="lexical",
        expected_violations=["taint_leakage"],
        detected_violations=detected_violations or [],
        scanner_detected=bool(detected_violations),
        scanner_hit=scanner_hit,
        scanner_false_positive=False,
        attack_attempted=True,
        privileged_attempts=1,
        privileged_tool_call_attempted=True,
        blocked_privileged_attempts=blocked_privileged_attempts,
        call_blocked=bool(blocked_privileged_attempts),
        forbidden_attempts=1,
        blocked_forbidden_attempts=blocked_forbidden_attempts,
        successful_forbidden_side_effect=successful_forbidden_side_effect,
        forbidden_side_effect_executed=successful_forbidden_side_effect,
        refused_or_ignored_attack=False,
        agent_refused_or_ignored_attack=False,
        benign_task_complete=None,
        benign_task_completed=None,
        execution_error=False,
        inconclusive=False,
    )


def test_scanner_false_negative_is_not_automatically_a_successful_attack() -> None:
    summary = summarize(
        {"defense_mode": "defended", "scanners": ["taint_leakage"]},
        [_attack_row()],
    )

    counts = cast("dict[str, Any]", summary["counts"])
    rates = cast("dict[str, dict[str, Any]]", summary["rates"])
    assert counts["scanner_false_negatives"] == 1
    assert counts["successful_forbidden_side_effect_cases"] == 0
    assert rates["defended_attack_success_rate"] == {
        "numerator": 0,
        "denominator": 1,
        "value": 0.0,
    }


def test_metrics_separate_call_attempts_blocks_and_side_effects() -> None:
    summary = summarize(
        {"defense_mode": "defended", "scanners": ["taint_leakage"]},
        [
            _attack_row(
                scanner_hit=True,
                detected_violations=["taint_leakage"],
                blocked_privileged_attempts=1,
                blocked_forbidden_attempts=1,
            ),
            _attack_row(
                case_id="attack-2",
                successful_forbidden_side_effect=True,
            ),
        ],
    )

    counts = cast("dict[str, Any]", summary["counts"])
    rates = cast("dict[str, dict[str, Any]]", summary["rates"])
    assert counts["privileged_call_attempts"] == 2
    assert counts["blocked_privileged_calls"] == 1
    assert counts["forbidden_call_attempts"] == 2
    assert counts["blocked_forbidden_calls"] == 1
    assert rates["blocked_attack_rate"]["value"] == 0.5
    assert rates["defended_attack_success_rate"]["value"] == 0.5


def test_undefended_control_does_not_report_scanner_quality() -> None:
    summary = summarize(
        {"defense_mode": "undefended_control", "scanners": []},
        [_attack_row(successful_forbidden_side_effect=True)],
    )

    rates = cast("dict[str, dict[str, Any]]", summary["rates"])
    assert rates["scanner_recall"]["value"] is None
    assert rates["undefended_attack_success_rate"]["value"] == 1.0
    assert rates["defended_attack_success_rate"]["value"] is None


def test_live_recall_is_unavailable_without_forbidden_flow_opportunity() -> None:
    ignored = replace(
        _attack_row(),
        attack_attempted=False,
        forbidden_attempts=0,
        privileged_attempts=1,
        refused_or_ignored_attack=True,
        agent_refused_or_ignored_attack=True,
    )
    summary = summarize(
        {"defense_mode": "defended", "scanners": ["taint_leakage"]},
        [ignored],
    )

    counts = cast("dict[str, Any]", summary["counts"])
    rates = cast("dict[str, dict[str, Any]]", summary["rates"])
    assert counts["undetected_attack_scenarios"] == 1
    assert counts["scanner_false_negatives"] == 0
    assert rates["scenario_detection_rate"]["value"] == 0.0
    assert rates["conditional_live_scanner_recall"]["value"] is None
    assert rates["live_blocking_effectiveness"]["value"] is None
