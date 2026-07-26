"""Validate and independently rescore one or more frozen evaluation runs.

The command hard-fails on config-hash, saved-verdict, trust-policy, or
online/offline disagreement and can emit a compact machine-readable receipt.

Usage:
    uv run python scripts/verify_evidence.py RUN_DIR [RUN_DIR ...]
    uv run python scripts/verify_evidence.py RUN_DIR --json-out receipt.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from configs import config_hash, load_config
from core import Monitor
from core.trust import DEFAULT_TRUST_POLICY, TRUST_POLICY_ATTR, TrustPolicy
from evaluation.integrity import EvidenceIntegrityError, load_validated_violations
from evaluation.store_jsonl import load_validated_run
from projections import OTLPProjection
from registry import load_builtins, resolve

if TYPE_CHECKING:
    from configs import RunConfig
    from core import Scanner, Task


def _build_scanners(cfg: RunConfig) -> list[Scanner]:
    scanners: list[Scanner] = []
    for spec in cfg.scanners:
        scanner_cls = resolve("scanner", spec.id)
        scanners.append(cast("Scanner", scanner_cls(**spec.params)))
    return scanners


def _resolved_policy(scanners: list[Scanner]) -> TrustPolicy:
    policies = [
        scanner.trust_policy
        for scanner in scanners
        if isinstance(scanner.trust_policy, TrustPolicy)
    ]
    if policies and any(policy != policies[0] for policy in policies[1:]):
        raise EvidenceIntegrityError("configured scanners resolve conflicting trust policies")
    return policies[0] if policies else DEFAULT_TRUST_POLICY


def verify_run(run_dir: Path) -> dict[str, object]:
    """Validate a run and return a compact verification receipt."""
    cfg = load_config(run_dir / "cfg.yaml")
    if cfg.run.id != run_dir.name:
        raise EvidenceIntegrityError(
            f"{run_dir}: frozen run id {cfg.run.id!r} does not match directory name "
            f"{run_dir.name!r}"
        )
    frozen_hash = config_hash(cfg)
    load_builtins()
    suite_cls = resolve("suite", cfg.suite.id)
    suite = cast("Any", suite_cls(**cfg.suite.params))
    scanners = _build_scanners(cfg)
    policy = _resolved_policy(scanners)
    wanted = set(cfg.suite.case_ids)

    rows: list[dict[str, object]] = []
    for case_raw in suite.cases():
        case = cast("Task", case_raw)
        if wanted and case.id not in wanted:
            continue
        case_dir = run_dir / "cases" / case.id
        spans = load_validated_run(
            case_dir.parent,
            case.id,
            expected_config_hash=frozen_hash,
        )
        trace = OTLPProjection(case.id).project(spans)
        saved = load_validated_violations(
            case_dir / "violations.json",
            expected_hash=frozen_hash,
        )
        saved_types = [item.get("type") for item in saved]
        rescored = Monitor(scanners).scan(trace, gt=case.ground_truth)
        rescored_types = [violation.type for violation in rescored]
        if saved_types != rescored_types:
            raise EvidenceIntegrityError(
                f"{case_dir}: saved verdicts {saved_types!r} disagree with "
                f"independent rescore {rescored_types!r}"
            )

        tools = trace.tool_steps()
        stale = [
            step.name
            for step in tools
            if step.metadata.get(TRUST_POLICY_ATTR) != policy.fingerprint
        ]
        if stale:
            raise EvidenceIntegrityError(
                f"{case_dir}: missing or stale trust-policy fingerprint on tools {stale!r}; "
                f"expected {policy.fingerprint!r}"
            )

        online_blocks = sum(step.metadata.get("taicf.gate.decision") == "block" for step in tools)
        offline_taint = sum(violation.type == "taint_leakage" for violation in rescored)
        if bool(online_blocks) != bool(offline_taint):
            raise EvidenceIntegrityError(
                f"{case_dir}: online blocks ({online_blocks}) disagree with offline "
                f"taint verdicts ({offline_taint})"
            )
        rows.append(
            {
                "case_id": case.id,
                "span_count": len(spans),
                "tool_steps": len(tools),
                "online_blocks": online_blocks,
                "offline_violations": rescored_types,
                "config_hash_valid": True,
                "policy_fingerprint_valid": True,
                "online_offline_agreement": True,
            }
        )

    return {
        "schema_version": 1,
        "run_id": cfg.run.id,
        "config_hash": frozen_hash,
        "trust_policy_fingerprint": policy.fingerprint,
        "cases": rows,
        "case_count": len(rows),
        "config_hashes_valid": True,
        "saved_violations_valid": True,
        "policy_fingerprints_valid": True,
        "online_offline_agreement": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dirs", nargs="+", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    receipts = [verify_run(path) for path in args.run_dirs]
    for receipt in receipts:
        print(
            f"{receipt['run_id']}: cases={receipt['case_count']} "
            f"config_hash={receipt['config_hash']} "
            f"policy={receipt['trust_policy_fingerprint']} "
            "online_offline=match"
        )
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps({"runs": receipts}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
