from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Protocol

from .adapters import LifeguardExtractsAdapterLayer
from .checkpoint_store import RuntimeCheckpointStore
from .evidence_store import EvidenceStore
from .live_intelligence import LiveDataError, LiveDataReport, LiveIntelligenceClient
from .open_source_guardrails import OpenSourceModeViolation, enforce_open_source_mode
from .output_contracts import OutputContractError, validate_node_output_contract
from .policy_compiler import CompiledPolicy, compile_policy
from .runtime_policy_middleware import PolicyExecutionMiddleware
from .spec_schema import AgentSpec, ConfigValidationError, load_spec
from .threat_model import validate_policy_against_threats
from .tool_execution import ToolExecutionEngine, ToolExecutionResult
from .verification_pipeline import CheckResult, VerificationPipeline, VerificationReport


class LangGraphRuntimeError(RuntimeError):
    """Base exception for Lang Graph runtime errors."""


class LangGraphUnavailableError(LangGraphRuntimeError):
    """Raised when Lang Graph is not installed or cannot be loaded."""


class LangGraphStateError(LangGraphRuntimeError):
    """Raised when graph state is incomplete or invalid."""


class GraphRunner(Protocol):
    def invoke(self, input: dict[str, Any]) -> dict[str, Any]:
        """Runs the graph and returns final state."""


NodeCallable = Callable[[dict[str, Any]], dict[str, Any]]
GraphRunnerFactory = Callable[[tuple[tuple[str, NodeCallable], ...]], GraphRunner]


@dataclass(frozen=True)
class LangGraphRuntimeReport:
    passed: bool
    spec: AgentSpec
    policy: CompiledPolicy | None
    threat_findings: tuple[str, ...]
    live_data_report: LiveDataReport | None
    live_data_error: str | None
    verification_report: VerificationReport
    evidence_path: Path
    run_id: str
    checkpoint_path: Path | None = None
    resumed_from: Path | None = None
    replay_of: Path | None = None
    replay_match: bool | None = None


class LangGraphRuntimeAdapter:
    """Deterministic Lang Graph runtime for secure agent design verification."""

    def __init__(
        self,
        evidence_store: EvidenceStore,
        adapter_layer: LifeguardExtractsAdapterLayer | None = None,
        repo_path: Path | None = None,
        intelligence_client: LiveIntelligenceClient | None = None,
        graph_runner_factory: GraphRunnerFactory | None = None,
        policy_middleware: PolicyExecutionMiddleware | None = None,
        tool_executor: ToolExecutionEngine | None = None,
    ) -> None:
        self.evidence_store = evidence_store
        self.adapter_layer = adapter_layer or LifeguardExtractsAdapterLayer()
        self.repo_path = repo_path
        self.intelligence_client = intelligence_client or LiveIntelligenceClient()
        self.policy_middleware = policy_middleware or PolicyExecutionMiddleware()
        self.tool_executor = tool_executor or ToolExecutionEngine(
            workspace_path=self.repo_path or Path.cwd()
        )
        self._graph_runner_factory = graph_runner_factory or _build_langgraph_runner
        self._verification_pipeline = VerificationPipeline(
            evidence_store=self.evidence_store,
            adapter_layer=self.adapter_layer,
            repo_path=self.repo_path,
            intelligence_client=self.intelligence_client,
        )
        self._approved_by = ""
        self._approval_id = ""
        self._approval_notes = ""

    def run(
        self,
        spec: AgentSpec | None = None,
        spec_path: str | Path | None = None,
        run_id: str | None = None,
        checkpoint_dir: str | Path | None = None,
        resume_from: str | Path | None = None,
        approved_by: str | None = None,
        approval_id: str | None = None,
        approval_notes: str | None = None,
    ) -> LangGraphRuntimeReport:
        previous_approval = (self._approved_by, self._approval_id, self._approval_notes)
        self._approved_by = approved_by.strip() if approved_by else ""
        self._approval_id = approval_id.strip() if approval_id else ""
        self._approval_notes = approval_notes.strip() if approval_notes else ""
        try:
            enforce_open_source_mode()
        except OpenSourceModeViolation as exc:
            self._approved_by, self._approval_id, self._approval_notes = previous_approval
            raise LangGraphRuntimeError(str(exc)) from exc

        try:
            checkpoint_root = (
                Path(checkpoint_dir)
                if checkpoint_dir is not None
                else self.evidence_store.path.parent / "checkpoints"
            )
            checkpoint_store = RuntimeCheckpointStore(checkpoint_root)
            initial_state, resolved_run_id, resumed_from_path = self._load_initial_state(
                checkpoint_store=checkpoint_store,
                spec=spec,
                spec_path=spec_path,
                run_id=run_id,
                resume_from=resume_from,
            )

            graph_nodes = self._graph_nodes(checkpoint_store=checkpoint_store)
            graph_runner = self._graph_runner_factory(graph_nodes)
            final_state = graph_runner.invoke(initial_state)
            return self._build_runtime_report(
                state=final_state,
                run_id=resolved_run_id,
                resumed_from=resumed_from_path,
            )
        finally:
            self._approved_by, self._approval_id, self._approval_notes = previous_approval

    def resume(
        self,
        checkpoint_path: str | Path,
        spec: AgentSpec | None = None,
        spec_path: str | Path | None = None,
        run_id: str | None = None,
        checkpoint_dir: str | Path | None = None,
        approved_by: str | None = None,
        approval_id: str | None = None,
        approval_notes: str | None = None,
    ) -> LangGraphRuntimeReport:
        return self.run(
            spec=spec,
            spec_path=spec_path,
            run_id=run_id,
            checkpoint_dir=checkpoint_dir,
            resume_from=checkpoint_path,
            approved_by=approved_by,
            approval_id=approval_id,
            approval_notes=approval_notes,
        )

    def replay(
        self,
        checkpoint_path: str | Path,
        spec: AgentSpec | None = None,
        spec_path: str | Path | None = None,
        run_id: str | None = None,
        checkpoint_dir: str | Path | None = None,
        approved_by: str | None = None,
        approval_id: str | None = None,
        approval_notes: str | None = None,
    ) -> LangGraphRuntimeReport:
        checkpoint_target = Path(checkpoint_path)
        checkpoint_root = (
            Path(checkpoint_dir)
            if checkpoint_dir is not None
            else checkpoint_target.parent
        )
        checkpoint_store = RuntimeCheckpointStore(checkpoint_root)
        baseline_checkpoint = checkpoint_store.load_checkpoint(checkpoint_target)
        replay_run_id = run_id or f"{baseline_checkpoint.run_id}-replay-{uuid.uuid4().hex[:6]}"

        replay_report = self.run(
            spec=spec,
            spec_path=spec_path,
            run_id=replay_run_id,
            checkpoint_dir=checkpoint_root,
            resume_from=checkpoint_target,
            approved_by=approved_by,
            approval_id=approval_id,
            approval_notes=approval_notes,
        )

        baseline_signature = _comparison_signature_from_state(baseline_checkpoint.state)
        replay_signature = _comparison_signature_from_report(replay_report)
        replay_match = baseline_signature == replay_signature
        self.evidence_store.append(
            "langgraph.runtime.replay.compare",
            "pass" if replay_match else "fail",
            {
                "replay_of": str(checkpoint_target),
                "run_id": replay_run_id,
                "baseline_signature": baseline_signature,
                "replay_signature": replay_signature,
            },
        )
        return replace(
            replay_report,
            replay_of=checkpoint_target,
            replay_match=replay_match,
        )

    def _load_initial_state(
        self,
        checkpoint_store: RuntimeCheckpointStore,
        spec: AgentSpec | None,
        spec_path: str | Path | None,
        run_id: str | None,
        resume_from: str | Path | None,
    ) -> tuple[dict[str, Any], str, Path | None]:
        if resume_from is None:
            if spec is None and spec_path is None:
                raise LangGraphStateError(
                    "Provide spec, spec_path, or resume_from for runtime execution."
                )
            resolved_run_id = run_id or checkpoint_store.generate_run_id()
            state: dict[str, Any] = {
                "spec": spec,
                "spec_path": str(spec_path) if spec_path is not None else None,
                "completed_nodes": (),
                "run_id": resolved_run_id,
            }
            return state, resolved_run_id, None

        checkpoint = checkpoint_store.load_checkpoint(resume_from)
        state = dict(checkpoint.state)
        if spec is not None:
            state["spec"] = spec
        if spec_path is not None:
            state["spec_path"] = str(spec_path)

        completed_nodes = state.get("completed_nodes")
        if not isinstance(completed_nodes, tuple):
            state["completed_nodes"] = (checkpoint.node_name,)
        state["checkpoint_path"] = str(checkpoint.path)

        resolved_run_id = run_id or checkpoint.run_id or checkpoint_store.generate_run_id()
        state["run_id"] = resolved_run_id
        return state, resolved_run_id, checkpoint.path

    def _graph_nodes(
        self, checkpoint_store: RuntimeCheckpointStore
    ) -> tuple[tuple[str, NodeCallable], ...]:
        base_nodes: tuple[tuple[str, NodeCallable], ...] = (
            ("load_spec", self._node_load_spec),
            ("collect_live_intelligence", self._node_collect_live_intelligence),
            ("compile_policy", self._node_compile_policy),
            ("policy_runtime_gate", self._node_policy_runtime_gate),
            ("execute_tools", self._node_execute_tools),
            ("threat_checks", self._node_threat_checks),
            ("verification", self._node_verification),
        )
        return tuple(
            (name, self._wrap_node(name, node, checkpoint_store))
            for name, node in base_nodes
        )

    def _wrap_node(
        self,
        node_name: str,
        node: NodeCallable,
        checkpoint_store: RuntimeCheckpointStore,
    ) -> NodeCallable:
        def wrapped(state: dict[str, Any]) -> dict[str, Any]:
            completed_nodes_value = state.get("completed_nodes", ())
            completed_nodes = tuple(str(item) for item in completed_nodes_value)
            if node_name in completed_nodes:
                merged_state = dict(state)
                merged_state["completed_nodes"] = completed_nodes
                return merged_state

            try:
                output = node(state)
                validate_node_output_contract(node_name, output)
            except OutputContractError as exc:
                self.evidence_store.append(
                    "langgraph.runtime.output_contract",
                    "fail",
                    {"node_name": node_name, "error": str(exc)},
                )
                raise LangGraphStateError(f"Output contract failed for node '{node_name}': {exc}") from exc

            merged_state = dict(state)
            merged_state.update(output)

            resolved_run_id = str(
                merged_state.get("run_id")
                or state.get("run_id")
                or checkpoint_store.generate_run_id()
            )
            merged_state["run_id"] = resolved_run_id

            updated_completed = tuple((*completed_nodes, node_name))
            merged_state["completed_nodes"] = updated_completed

            checkpoint = checkpoint_store.save_checkpoint(
                run_id=resolved_run_id,
                node_name=node_name,
                sequence=len(updated_completed),
                state=merged_state,
            )
            self.evidence_store.append(
                "langgraph.runtime.checkpoint.saved",
                "pass",
                {
                    "node_name": node_name,
                    "run_id": resolved_run_id,
                    "checkpoint_path": str(checkpoint.path),
                },
            )

            merged_state["checkpoint_path"] = str(checkpoint.path)
            return merged_state

        return wrapped

    def _build_runtime_report(
        self,
        state: dict[str, Any],
        run_id: str,
        resumed_from: Path | None,
    ) -> LangGraphRuntimeReport:
        final_spec = state.get("spec")
        if not isinstance(final_spec, AgentSpec):
            raise LangGraphStateError("Graph completed without a valid agent specification.")

        verification_report = state.get("verification_report")
        if not isinstance(verification_report, VerificationReport):
            raise LangGraphStateError("Graph completed without verification report output.")

        policy = state.get("policy")
        if not isinstance(policy, CompiledPolicy):
            policy = None

        threat_findings_value = state.get("threat_findings", ())
        threat_findings = tuple(str(item) for item in threat_findings_value)

        live_data_report = state.get("live_data_report")
        if not isinstance(live_data_report, LiveDataReport):
            live_data_report = None

        live_data_error = state.get("live_data_error")
        if live_data_error is not None:
            live_data_error = str(live_data_error)

        checkpoint_path_value = state.get("checkpoint_path")
        checkpoint_path = (
            Path(str(checkpoint_path_value))
            if isinstance(checkpoint_path_value, str) and checkpoint_path_value.strip()
            else None
        )

        return LangGraphRuntimeReport(
            passed=verification_report.passed,
            spec=final_spec,
            policy=policy,
            threat_findings=threat_findings,
            live_data_report=live_data_report,
            live_data_error=live_data_error,
            verification_report=verification_report,
            evidence_path=self.evidence_store.path,
            run_id=run_id,
            checkpoint_path=checkpoint_path,
            resumed_from=resumed_from,
        )

    def _node_load_spec(self, state: dict[str, Any]) -> dict[str, Any]:
        try:
            spec = state.get("spec")
            if not isinstance(spec, AgentSpec):
                spec_path = state.get("spec_path")
                if not spec_path:
                    raise LangGraphStateError("Missing spec_path for load_spec node.")
                spec = load_spec(spec_path)
        except Exception as exc:
            self.evidence_store.append(
                "langgraph.runtime.load_spec",
                "fail",
                {"error": str(exc)},
            )
            raise LangGraphStateError(f"load_spec failed: {exc}") from exc

        self.evidence_store.append(
            "langgraph.runtime.load_spec",
            "pass",
            {"agent_name": spec.name, "risk_level": spec.risk_level},
        )
        return {"spec": spec}

    def _node_collect_live_intelligence(self, state: dict[str, Any]) -> dict[str, Any]:
        spec = state.get("spec")
        if not isinstance(spec, AgentSpec):
            raise LangGraphStateError("collect_live_intelligence requires a valid spec.")

        settings = spec.live_data
        if not settings.enabled:
            self.evidence_store.append(
                "langgraph.runtime.collect_live_intelligence",
                "pass",
                {"enabled": False},
            )
            return {
                "spec": spec,
                "live_data_report": None,
                "live_data_error": None,
            }

        query = settings.query.strip() or spec.description
        try:
            report = self.intelligence_client.collect_latest(
                query=query,
                settings=settings,
                risk_level=spec.risk_level,
            )
        except LiveDataError as exc:
            self.evidence_store.append(
                "langgraph.runtime.collect_live_intelligence",
                "fail",
                {
                    "provider": settings.provider,
                    "model": settings.model,
                    "query": query,
                    "error": str(exc),
                },
            )
            return {
                "spec": spec,
                "live_data_report": None,
                "live_data_error": str(exc),
            }

        self.evidence_store.append(
            "langgraph.runtime.collect_live_intelligence",
            "pass",
            {
                "provider": report.provider,
                "model": report.model,
                "query": report.query,
                "citation_count": len(report.citations),
                "attempts": [item.to_dict() for item in report.attempts],
                "trust_assessment": report.assessment.to_dict(),
            },
        )
        return {
            "spec": spec,
            "live_data_report": report,
            "live_data_error": None,
        }

    def _node_compile_policy(self, state: dict[str, Any]) -> dict[str, Any]:
        spec = state.get("spec")
        if not isinstance(spec, AgentSpec):
            raise LangGraphStateError("compile_policy requires a valid spec.")

        try:
            policy = compile_policy(spec)
        except ConfigValidationError as exc:
            self.evidence_store.append(
                "langgraph.runtime.compile_policy",
                "fail",
                {"error": str(exc)},
            )
            return {
                "spec": spec,
                "policy": None,
                "policy_error": str(exc),
            }

        self.evidence_store.append(
            "langgraph.runtime.compile_policy",
            "pass",
            {
                "network_mode": policy.network_mode,
                "requires_human_approval": policy.requires_human_approval,
            },
        )
        return {
            "spec": spec,
            "policy": policy,
            "policy_error": None,
        }

    def _node_policy_runtime_gate(self, state: dict[str, Any]) -> dict[str, Any]:
        spec = state.get("spec")
        if not isinstance(spec, AgentSpec):
            raise LangGraphStateError("policy_runtime_gate requires a valid spec.")

        policy = state.get("policy")
        if policy is not None and not isinstance(policy, CompiledPolicy):
            raise LangGraphStateError("policy_runtime_gate received invalid policy type.")

        decisions = self.policy_middleware.evaluate_spec_tools(spec=spec, policy=policy)
        decision_payload = tuple(decision.to_dict() for decision in decisions)
        blocked_payload = tuple(item for item in decision_payload if not bool(item["allowed"]))
        passed = not blocked_payload

        self.evidence_store.append(
            "langgraph.runtime.policy_runtime_gate",
            "pass" if passed else "fail",
            {
                "tool_count": len(decision_payload),
                "blocked_count": len(blocked_payload),
            },
        )
        return {
            "spec": spec,
            "policy": policy,
            "tool_gate_passed": passed,
            "tool_gate_results": decision_payload,
            "blocked_tool_decisions": blocked_payload,
        }

    def _node_execute_tools(self, state: dict[str, Any]) -> dict[str, Any]:
        spec = state.get("spec")
        if not isinstance(spec, AgentSpec):
            raise LangGraphStateError("execute_tools requires a valid spec.")

        policy = state.get("policy")
        if not isinstance(policy, CompiledPolicy):
            error = "Tool execution skipped because policy is unavailable."
            self.evidence_store.append(
                "langgraph.runtime.execute_tools",
                "fail",
                {"error": error},
            )
            return {
                "spec": spec,
                "tool_execution_passed": False,
                "tool_execution_results": (),
                "tool_execution_error": error,
            }

        tool_gate_passed = bool(state.get("tool_gate_passed", False))
        if not tool_gate_passed:
            self.evidence_store.append(
                "langgraph.runtime.execute_tools",
                "pass",
                {
                    "executed_count": 0,
                    "skipped_due_to_policy_gate": True,
                },
            )
            return {
                "spec": spec,
                "tool_execution_passed": True,
                "tool_execution_results": (),
                "tool_execution_error": None,
            }

        approval_required_indexes = [
            index
            for index, tool in enumerate(spec.tools)
            if tool.can_access_network or tool.can_write_files
        ]
        approval_required = bool(approval_required_indexes)
        approval_provided = bool(self._approved_by and self._approval_id)
        blocked_indexes = (
            set(approval_required_indexes) if approval_required and not approval_provided else set()
        )
        blocked_tools = [spec.tools[index].name for index in sorted(blocked_indexes)]
        if blocked_indexes:
            self.evidence_store.append(
                "langgraph.runtime.tool_execution.approval_gate",
                "fail",
                {
                    "approval_required": approval_required,
                    "approval_provided": approval_provided,
                    "blocked_tool_count": len(blocked_indexes),
                    "blocked_tools": blocked_tools,
                    "reason": (
                        "Human approval is required for tools that can access network "
                        "or write files."
                    ),
                    "approved_by": self._approved_by or None,
                    "approval_id": self._approval_id or None,
                },
            )
        else:
            self.evidence_store.append(
                "langgraph.runtime.tool_execution.approval_gate",
                "pass",
                {
                    "approval_required": approval_required,
                    "approval_provided": approval_provided,
                    "blocked_tool_count": 0,
                    "blocked_tools": (),
                    "reason": "",
                    "approved_by": self._approved_by or None,
                    "approval_id": self._approval_id or None,
                },
            )

        executed_results: tuple[ToolExecutionResult, ...] = ()
        if blocked_indexes:
            tools_to_execute = [
                tool for index, tool in enumerate(spec.tools) if index not in blocked_indexes
            ]
            if tools_to_execute:
                executed_spec = replace(spec, tools=tuple(tools_to_execute))
                executed_results = self.tool_executor.execute_spec_tools(
                    spec=executed_spec,
                    policy=policy,
                )
        else:
            executed_results = self.tool_executor.execute_spec_tools(spec=spec, policy=policy)

        executed_iter = iter(executed_results)
        merged_results: list[ToolExecutionResult] = []
        for index, tool in enumerate(spec.tools):
            if index in blocked_indexes:
                merged_results.append(
                    ToolExecutionResult(
                        tool_name=tool.name,
                        command=tool.command,
                        runtime_environment=spec.runtime_environment,
                        backend="approval_gate",
                        image=getattr(self.tool_executor, "image", ""),
                        passed=False,
                        exit_code=1,
                        stdout="",
                        stderr="",
                        reason=(
                            "Human approval is required for tools that can access network "
                            "or write files."
                        ),
                        policy_violations=(),
                    )
                )
            else:
                merged_results.append(next(executed_iter))
        results = tuple(merged_results)
        result_payload = tuple(item.to_dict() for item in results)
        passed = all(bool(item.get("passed", False)) for item in result_payload) if result_payload else True
        failed_count = len([item for item in result_payload if not bool(item.get("passed", False))])
        policy_violations: list[dict[str, object]] = []
        for item in result_payload:
            raw_violations = item.get("policy_violations", ())
            if not isinstance(raw_violations, (list, tuple)):
                continue
            cleaned = [str(value).strip() for value in raw_violations if str(value).strip()]
            if not cleaned:
                continue
            policy_violations.append(
                {
                    "tool_name": str(item.get("tool_name", "")).strip(),
                    "violations": cleaned,
                }
            )
        if policy_violations:
            self.evidence_store.append(
                "langgraph.runtime.sandbox_policy_violation",
                "fail",
                {
                    "violation_count": len(policy_violations),
                    "tool_violations": policy_violations,
                },
            )
            passed = False
        self.evidence_store.append(
            "langgraph.runtime.execute_tools",
            "pass" if passed else "fail",
            {
                "executed_count": len(result_payload),
                "failed_count": failed_count,
                "policy_violation_count": len(policy_violations),
            },
        )
        error_message = None
        if policy_violations:
            violation_summary = "; ".join(
                f"{entry['tool_name']}: {', '.join(entry['violations'])}"
                for entry in policy_violations
            )
            error_message = "Sandbox policy violations detected. " + violation_summary
        elif not passed:
            error_message = "One or more tool commands failed in sandbox."
        return {
            "spec": spec,
            "tool_execution_passed": passed,
            "tool_execution_results": result_payload,
            "tool_execution_error": error_message,
        }

    def _node_threat_checks(self, state: dict[str, Any]) -> dict[str, Any]:
        spec = state.get("spec")
        if not isinstance(spec, AgentSpec):
            raise LangGraphStateError("threat_checks requires a valid spec.")

        policy = state.get("policy")
        if not isinstance(policy, CompiledPolicy):
            findings = ("Threat checks skipped because policy is unavailable.",)
            self.evidence_store.append(
                "langgraph.runtime.threat_checks",
                "fail",
                {"findings": list(findings)},
            )
            return {
                "spec": spec,
                "policy": None,
                "threat_findings": findings,
            }

        findings = tuple(validate_policy_against_threats(spec, policy))
        status = "pass" if not findings else "fail"
        self.evidence_store.append(
            "langgraph.runtime.threat_checks",
            status,
            {"findings": list(findings)},
        )
        return {
            "spec": spec,
            "policy": policy,
            "threat_findings": findings,
        }

    def _node_verification(self, state: dict[str, Any]) -> dict[str, Any]:
        spec = state.get("spec")
        if not isinstance(spec, AgentSpec):
            raise LangGraphStateError("verification requires a valid spec.")

        report = self._verification_pipeline.run(spec)
        blocked_payload = _normalize_blocked_decisions(state.get("blocked_tool_decisions"))
        execution_payload = _normalize_tool_execution_results(state.get("tool_execution_results"))
        tool_execution_passed = bool(state.get("tool_execution_passed", True))
        tool_execution_error = str(state.get("tool_execution_error", "")).strip()
        if blocked_payload:
            blocked_message = "; ".join(
                f"{item['tool_name']}: {item['reason']}" for item in blocked_payload
            )
            blocked_check = CheckResult(
                name="policy_execution_gate",
                passed=False,
                message=blocked_message,
            )
            report = VerificationReport(
                passed=False,
                results=tuple((*report.results, blocked_check)),
                policy=report.policy,
                evidence_path=report.evidence_path,
            )
            self.evidence_store.append(
                "langgraph.runtime.policy_execution_gate",
                "fail",
                {"blocked_tool_count": len(blocked_payload)},
            )
        else:
            self.evidence_store.append(
                "langgraph.runtime.policy_execution_gate",
                "pass",
                {"blocked_tool_count": 0},
            )

        if tool_execution_passed:
            self.evidence_store.append(
                "langgraph.runtime.tool_execution_gate",
                "pass",
                {"executed_tool_count": len(execution_payload)},
            )
        else:
            failed_tool_messages = [
                f"{item['tool_name']}: {item['reason']}"
                for item in execution_payload
                if not bool(item.get("passed", False))
            ]
            failure_message = "; ".join(failed_tool_messages)
            if not failure_message:
                failure_message = tool_execution_error or "Tool execution failed in hardened sandbox."
            execution_check = CheckResult(
                name="tool_execution_gate",
                passed=False,
                message=failure_message,
            )
            report = VerificationReport(
                passed=False,
                results=tuple((*report.results, execution_check)),
                policy=report.policy,
                evidence_path=report.evidence_path,
            )
            self.evidence_store.append(
                "langgraph.runtime.tool_execution_gate",
                "fail",
                {"executed_tool_count": len(execution_payload)},
            )

        model_context_protocol_check = next(
            (item for item in report.results if item.name == "model_context_protocol_gating"),
            None,
        )
        if model_context_protocol_check is not None:
            self.evidence_store.append(
                "langgraph.runtime.model_context_protocol_gating",
                "pass" if model_context_protocol_check.passed else "fail",
                {"message": model_context_protocol_check.message},
            )

        self.evidence_store.append(
            "langgraph.runtime.verification",
            "pass" if report.passed else "fail",
            {"check_count": len(report.results)},
        )
        return {
            "spec": spec,
            "verification_report": report,
        }


def _build_langgraph_runner(nodes: tuple[tuple[str, NodeCallable], ...]) -> GraphRunner:
    if not nodes:
        raise LangGraphStateError("Graph requires at least one node.")

    try:
        from langgraph.graph import END, START, StateGraph
    except Exception as exc:
        raise LangGraphUnavailableError(
            "Lang Graph runtime unavailable. Install optional dependencies with "
            "'pip install lifeguard[graph_runtime]'."
        ) from exc

    graph = StateGraph(dict)
    for name, node in nodes:
        graph.add_node(name, node)

    graph.add_edge(START, nodes[0][0])
    for current, following in zip(nodes, nodes[1:]):
        graph.add_edge(current[0], following[0])
    graph.add_edge(nodes[-1][0], END)

    return graph.compile()


def _normalize_blocked_decisions(value: Any) -> tuple[dict[str, str | bool], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    normalized: list[dict[str, str | bool]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        tool_name = str(item.get("tool_name", "")).strip()
        command = str(item.get("command", "")).strip()
        allowed = bool(item.get("allowed", False))
        reason = str(item.get("reason", "")).strip()
        normalized.append(
            {
                "tool_name": tool_name,
                "command": command,
                "allowed": allowed,
                "reason": reason,
            }
        )
    return tuple(normalized)


def _normalize_tool_execution_results(value: Any) -> tuple[dict[str, object], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    normalized: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        normalized.append(
            {
                "tool_name": str(item.get("tool_name", "")).strip(),
                "command": str(item.get("command", "")).strip(),
                "runtime_environment": str(item.get("runtime_environment", "")).strip(),
                "backend": str(item.get("backend", "")).strip(),
                "image": str(item.get("image", "")).strip(),
                "passed": bool(item.get("passed", False)),
                "exit_code": int(item.get("exit_code", 0)),
                "stdout": str(item.get("stdout", "")),
                "stderr": str(item.get("stderr", "")),
                "reason": str(item.get("reason", "")).strip(),
                "policy_violations": tuple(
                    str(value).strip()
                    for value in item.get("policy_violations", ())
                    if str(value).strip()
                )
                if isinstance(item.get("policy_violations", ()), (list, tuple))
                else (),
            }
        )
    return tuple(normalized)


def _comparison_signature_from_state(state: dict[str, Any]) -> dict[str, Any]:
    verification_report = state.get("verification_report")
    if isinstance(verification_report, VerificationReport):
        return {
            "passed": verification_report.passed,
            "checks": [
                {
                    "name": result.name,
                    "passed": result.passed,
                    "message": result.message,
                }
                for result in verification_report.results
            ],
        }
    policy = state.get("policy")
    threat_findings = state.get("threat_findings")
    return {
        "policy_present": isinstance(policy, CompiledPolicy),
        "threat_findings": list(threat_findings) if isinstance(threat_findings, (list, tuple)) else [],
    }


def _comparison_signature_from_report(report: LangGraphRuntimeReport) -> dict[str, Any]:
    return {
        "passed": report.verification_report.passed,
        "checks": [
            {
                "name": result.name,
                "passed": result.passed,
                "message": result.message,
            }
            for result in report.verification_report.results
        ],
    }


def default_langgraph_runtime(
    evidence_path: str | Path,
    repo_path: str | Path | None = None,
    adapter_layer: LifeguardExtractsAdapterLayer | None = None,
    intelligence_client: LiveIntelligenceClient | None = None,
    graph_runner_factory: GraphRunnerFactory | None = None,
    policy_middleware: PolicyExecutionMiddleware | None = None,
    tool_executor: ToolExecutionEngine | None = None,
) -> LangGraphRuntimeAdapter:
    resolved_repo_path = Path(repo_path) if repo_path is not None else None
    return LangGraphRuntimeAdapter(
        evidence_store=EvidenceStore(evidence_path),
        adapter_layer=adapter_layer,
        repo_path=resolved_repo_path,
        intelligence_client=intelligence_client,
        graph_runner_factory=graph_runner_factory,
        policy_middleware=policy_middleware,
        tool_executor=tool_executor,
    )
