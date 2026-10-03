from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from agent.investigate import investigate
from agent.llm import (
    FinalAnswer,
    LLMClient,
    LLMResponse,
    Message,
    RecordingClient,
    ReplayClient,
    ToolSpec,
)
from agent.ollama import DEFAULT_MODEL, OllamaClient
from agent.single_shot import single_shot
from contracts.models import EvaluationArm, IncidentRun, Inventory, Scenario
from detection.sigma import RuleSet, load_rules
from eval.arms import rules_only
from eval.metrics import EvalRow, row, summarize
from eval.report import render
from pipeline.run import (
    INVENTORY_FILE,
    REPO,
    RULES_DIR,
    Investigator,
    load_inventory,
    load_scenario,
    run_pipeline,
)

A1 = EvaluationArm.A1_RULES_ONLY
A2B = EvaluationArm.A2B_FULL_CONTEXT
A3 = EvaluationArm.A3_TOOL_USING_AGENT
AI_ARMS = (A2B, A3)
INVESTIGATORS: dict[EvaluationArm, Investigator] = {
    A1: rules_only,
    A2B: single_shot,
    A3: investigate,
}
CLOCK = datetime(2026, 10, 3, tzinfo=UTC)
SCENARIOS_DIR = REPO / "lab" / "scenarios"
CASE_FILES = ("auth.log", "scenario.yml")
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_RECORDINGS = REPO / "eval" / "recordings"
DEFAULT_RESULTS = REPO / "eval" / "results.json"
DEFAULT_REPORT = REPO / "docs" / "eval-results.md"
EXIT_USAGE = 2
MODEL_TIMEOUT_S = 1200.0


class NoModel:
    model_name = "none"

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        raise RuntimeError("the rules-only arm never calls a model")


class StallGuard:
    def __init__(self, inner: LLMClient, timeout_s: float) -> None:
        self._inner = inner
        self._timeout_s = timeout_s

    @property
    def model_name(self) -> str:
        return self._inner.model_name

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        try:
            return self._inner.complete(messages, tools)
        except httpx.TimeoutException:
            return FinalAnswer(
                payload={
                    "error": f"The model did not answer within {self._timeout_s:.0f} seconds."
                },
                elapsed_ms=int(self._timeout_s * 1000),
            )


@dataclass(frozen=True)
class Lab:
    inventory: Inventory
    rules: RuleSet
    scenarios: Path = SCENARIOS_DIR

    def run(self, case_id: str, arm: EvaluationArm, llm: LLMClient) -> tuple[Scenario, IncidentRun]:
        folder = self.scenarios / case_id
        scenario = load_scenario(folder / "scenario.yml")
        if scenario is None:
            raise ValueError(f"{case_id} has no scenario.yml")
        lines = (folder / "auth.log").read_text(encoding="utf-8").splitlines()
        run = run_pipeline(
            lines,
            case_id,
            self.inventory,
            llm,
            rules=self.rules,
            now=lambda: CLOCK,
            scenario=scenario,
            investigator=INVESTIGATORS[arm],
        )
        return scenario, run


def discover_cases(root: Path = SCENARIOS_DIR) -> list[str]:
    return sorted(
        folder.name
        for folder in root.iterdir()
        if all((folder / name).is_file() for name in CASE_FILES)
    )


def recording_path(recordings: Path, case_id: str, arm: EvaluationArm, repeat: int) -> Path:
    return recordings / f"{case_id}.{arm.value}.{repeat}.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m eval.run",
        description="Run the three arms over the labelled cases and write the results and report.",
    )
    parser.add_argument(
        "--llm",
        choices=["replay", "ollama"],
        default="replay",
        help="replay the recordings (default) or record fresh runs through Ollama first",
    )
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model tag")
    parser.add_argument("--repeats", type=int, default=3, help="runs per case for each AI arm")
    parser.add_argument("--cases", help="comma-separated case ids; defaults to every case")
    parser.add_argument("--recordings", type=Path, default=DEFAULT_RECORDINGS)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.repeats < 1:
        print("--repeats must be at least 1", file=sys.stderr)
        return EXIT_USAGE
    known = discover_cases()
    cases = known
    if args.cases:
        cases = sorted({name.strip() for name in args.cases.split(",") if name.strip()})
        unknown = [name for name in cases if name not in known]
        if unknown:
            print(f"unknown case: {', '.join(unknown)}", file=sys.stderr)
            print(f"known cases: {', '.join(known)}", file=sys.stderr)
            return EXIT_USAGE
    lab = Lab(load_inventory(INVENTORY_FILE), load_rules(RULES_DIR))
    if args.llm == "ollama":
        record_live(lab, cases, args)
    missing = [path for path in wanted_recordings(cases, args) if not path.is_file()]
    if missing:
        for path in missing:
            print(f"missing recording: {path}", file=sys.stderr)
        print(
            f"{len(missing)} recordings are missing; record them with --llm ollama", file=sys.stderr
        )
        return EXIT_USAGE
    rows = replay_all(lab, cases, args.recordings, args.repeats)
    write_text(args.results, json.dumps([r.model_dump(mode="json") for r in rows], indent=2) + "\n")
    write_text(args.report, render(rows, summarize(rows)))
    print(f"wrote {args.results}")
    print(f"wrote {args.report}")
    return 0


def wanted_recordings(cases: list[str], args: argparse.Namespace) -> list[Path]:
    return [
        recording_path(args.recordings, case_id, arm, repeat)
        for case_id in cases
        for arm in AI_ARMS
        for repeat in range(1, args.repeats + 1)
    ]


def record_live(lab: Lab, cases: list[str], args: argparse.Namespace) -> None:
    for case_id in cases:
        for arm in AI_ARMS:
            for repeat in range(1, args.repeats + 1):
                path = recording_path(args.recordings, case_id, arm, repeat)
                label = f"{case_id} {arm.value} {repeat}/{args.repeats}"
                if path.exists():
                    print(f"{label} skipped", flush=True)
                    continue
                started = time.perf_counter()
                model = OllamaClient(model=args.model, base_url=args.ollama_url)
                recorder = RecordingClient(StallGuard(model, MODEL_TIMEOUT_S))
                _, run = lab.run(case_id, arm, recorder)
                write_text(path, recorder.recording().model_dump_json(indent=2) + "\n")
                seconds = time.perf_counter() - started
                print(f"{label} {run.verdict.classification.value} {seconds:.1f}s", flush=True)


def replay_all(lab: Lab, cases: list[str], recordings: Path, repeats: int) -> list[EvalRow]:
    rows = []
    for case_id in cases:
        scenario, run = lab.run(case_id, A1, NoModel())
        rows.append(row(case_id, scenario, A1, 1, run))
        for arm in AI_ARMS:
            for repeat in range(1, repeats + 1):
                client = ReplayClient.from_file(recording_path(recordings, case_id, arm, repeat))
                scenario, run = lab.run(case_id, arm, client)
                rows.append(row(case_id, scenario, arm, repeat, run))
    return rows


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".tmp")
    partial.write_text(text, encoding="utf-8", newline="\n")
    os.replace(partial, path)


if __name__ == "__main__":
    sys.exit(main())
