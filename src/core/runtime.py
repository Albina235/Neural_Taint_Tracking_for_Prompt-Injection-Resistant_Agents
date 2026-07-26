"""Online (Gate) and offline (Monitor) scanner runtimes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.enums import Hook, StepKind
from core.scanner import Decision, ScanContext
from core.trace import Step
from core.trust import DEFAULT_TRUST_POLICY

if TYPE_CHECKING:
    from core.scanner import Scanner, Violation
    from core.task import GroundTruth
    from core.trace import Trace
    from core.trust import TrustPolicy


class Gate:
    """Online runtime.

    Runs ``PRE_TOOL`` and ``POST_TOOL`` scanners as a scaffold executes,
    accumulating the partial trace in ``_history``. A single violation from
    any scanner produces ``Decision(allow=False)``.
    """

    def __init__(
        self,
        scanners: list[Scanner],
        gt: GroundTruth | None = None,
    ) -> None:
        self._pre = [s for s in scanners if Hook.PRE_TOOL in s.hooks]
        self._post = [s for s in scanners if Hook.POST_TOOL in s.hooks]
        self._gt = gt
        self._history: list[Step] = []
        policies = [
            scanner.trust_policy for scanner in scanners if scanner.trust_policy is not None
        ]
        if policies and any(policy != policies[0] for policy in policies[1:]):
            msg = "Configured scanners resolved conflicting trust policies"
            raise ValueError(msg)
        self._trust_policy = policies[0] if policies else DEFAULT_TRUST_POLICY

    @property
    def trust_policy(self) -> TrustPolicy:
        """Resolved policy shared with tool instrumentation."""
        return self._trust_policy

    def tool_metadata(self, name: str, args: dict[str, object]) -> dict[str, object]:
        """Resolve canonical trust metadata for an online or instrumented step."""
        return self._trust_policy.metadata(name, args)

    def before_tool(
        self,
        name: str,
        args: dict[str, object],
        *,
        metadata: dict[str, object] | None = None,
    ) -> Decision:
        """Evaluate ``PRE_TOOL`` scanners against the pending call."""
        resolved = metadata if metadata is not None else self.tool_metadata(name, args)
        pending = Step(kind=StepKind.TOOL, name=name, args=args, metadata=resolved)
        violations: list[Violation] = []
        for scanner in self._pre:
            ctx = ScanContext(
                hook=Hook.PRE_TOOL,
                history=list(self._history),
                pending=pending,
                ground_truth=self._gt,
            )
            violations.extend(scanner.evaluate(ctx))
        if violations:
            return Decision(allow=False, reason=violations[0].type)
        return Decision(allow=True)

    def after_tool(
        self,
        name: str,
        args: dict[str, object],
        output: str,
        *,
        metadata: dict[str, object] | None = None,
    ) -> Decision:
        """Evaluate ``POST_TOOL`` scanners, then record the step in history."""
        resolved = metadata if metadata is not None else self.tool_metadata(name, args)
        completed = Step(
            kind=StepKind.TOOL,
            name=name,
            args=args,
            output=output,
            metadata=resolved,
        )
        violations: list[Violation] = []
        for scanner in self._post:
            ctx = ScanContext(
                hook=Hook.POST_TOOL,
                history=list(self._history),
                pending=completed,
                ground_truth=self._gt,
            )
            violations.extend(scanner.evaluate(ctx))
        self._history.append(completed)
        if violations:
            return Decision(allow=False, reason=violations[0].type)
        return Decision(allow=True)


class Monitor:
    """Offline runtime. Runs ``POST_TURN`` scanners over the full trace."""

    def __init__(self, scanners: list[Scanner]) -> None:
        self._scanners = [s for s in scanners if Hook.POST_TURN in s.hooks]

    def scan(
        self,
        trace: Trace,
        gt: GroundTruth | None = None,
    ) -> list[Violation]:
        """Run every registered ``POST_TURN`` scanner; collect all violations."""
        violations: list[Violation] = []
        for scanner in self._scanners:
            ctx = ScanContext(
                hook=Hook.POST_TURN,
                history=list(trace.steps),
                pending=None,
                ground_truth=gt,
            )
            violations.extend(scanner.evaluate(ctx))
        return violations
