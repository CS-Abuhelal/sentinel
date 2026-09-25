import { FACTOR } from "../../format";
import type { RiskScore } from "../../types/contracts";

export function Risk({ risk }: { risk: RiskScore }) {
  const factors = Object.entries(risk.factors);
  const scored = factors.filter(([, points]) => points > 0);
  return (
    <>
      <p className="lede">
        Scored from alert severity, the collected evidence and the lab inventory. The agent’s
        verdict is not an input.
      </p>
      <div className="risk">
        <p className="score">
          <span className="score-n">{risk.score}</span>
          <span className="score-of">/ 100</span>
          <span className={`sev sev--${risk.severity}`}>{risk.severity}</span>
        </p>
        <div
          className="risk-bar"
          role="img"
          aria-label={`Risk ${risk.score} of 100: ${scored
            .map(([name, points]) => `${FACTOR[name] ?? name} ${points}`)
            .join(", ")}`}
        >
          {scored.map(([name, points], index) => (
            <span
              key={name}
              className={`risk-seg risk-seg--${index % 5}`}
              style={{ width: `${points}%` }}
            />
          ))}
        </div>
        <table className="factors">
          <tbody>
            {factors.map(([name, points]) => {
              const index = scored.findIndex(([scoredName]) => scoredName === name);
              return (
                <tr key={name} className={points === 0 ? "muted" : undefined}>
                  <td>
                    <span
                      className={index >= 0 ? `swatch risk-seg--${index % 5}` : "swatch swatch--empty"}
                      aria-hidden="true"
                    />
                    {FACTOR[name] ?? name}
                  </td>
                  <td className="mono num">+{points}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}
