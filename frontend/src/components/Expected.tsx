import type { IncidentRun } from "../types/contracts";

export function isCorrect(run: IncidentRun): boolean | null {
  if (!run.scenario) return null;
  return run.scenario.expected_classification === run.verdict.classification;
}

export function ExpectedBadge({ run }: { run: IncidentRun }) {
  const correct = isCorrect(run);
  if (correct === null) return null;
  return (
    <span className={correct ? "check check--right" : "check check--wrong"}>
      {correct ? "Matches the expected outcome" : `Wrong: expected ${run.scenario!.expected_classification}`}
    </span>
  );
}

export function ExpectedNote({ run }: { run: IncidentRun }) {
  const { scenario } = run;
  const correct = isCorrect(run);
  if (!scenario || correct === null) return null;
  return (
    <div className={correct ? "expected" : "expected expected--wrong"}>
      <p>
        <span className="kicker">Expected outcome, labelled by hand</span>{" "}
        <strong className={`cls cls--${scenario.expected_classification}`}>
          {scenario.expected_classification}
        </strong>
      </p>
      <p>
        <strong>{scenario.title}.</strong> {scenario.description}
      </p>
      {!correct && (
        <p>
          The model got this one wrong. Nothing ran because of it: the policy engine below still
          requires a human before any action. The agent never saw this label.
        </p>
      )}
    </div>
  );
}
