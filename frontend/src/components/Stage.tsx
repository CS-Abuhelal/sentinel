import type { ReactNode } from "react";

type Props = {
  n: number;
  title: string;
  producer: string;
  agent?: boolean;
  children: ReactNode;
};

export function Stage({ n, title, producer, agent = false, children }: Props) {
  const id = `stage-${n}`;
  return (
    <li className={agent ? "stage stage--agent" : "stage"}>
      <span className="stage-marker" aria-hidden="true">
        {n}
      </span>
      <section className="stage-body" aria-labelledby={id}>
        <header className="stage-head">
          <h2 id={id}>{title}</h2>
          <span className="producer mono">{producer}</span>
        </header>
        {children}
      </section>
    </li>
  );
}
