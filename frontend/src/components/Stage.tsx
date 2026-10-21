import type { ReactNode } from "react";

export type StageState = "waiting" | "active" | "done";

export function stageState(step: number, finished: boolean, start: number, end: number): StageState {
  if (finished || step > end) return "done";
  if (step >= start) return "active";
  return "waiting";
}

type Props = {
  n: number;
  title: string;
  producer: string;
  agent?: boolean;
  state: StageState;
  children: ReactNode;
};

export function Stage({ n, title, producer, agent = false, state, children }: Props) {
  const id = `stage-${n}`;
  const classes = ["stage", `stage--${state}`, agent ? "stage--agent" : ""].filter(Boolean).join(" ");
  return (
    <li className={classes} aria-busy={state === "active" ? true : undefined}>
      <span className="stage-marker" aria-hidden="true">
        {n}
      </span>
      <section className="stage-body" aria-labelledby={id}>
        <header className="stage-head">
          <h2 id={id}>{title}</h2>
          <span className="producer mono">{producer}</span>
        </header>
        {state === "waiting" ? <p className="waiting">Waiting for the previous stage.</p> : <div className="reveal">{children}</div>}
      </section>
    </li>
  );
}
