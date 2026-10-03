# Evaluation results

Model: `ollama:qwen3:14b`. 8 cases, 3 runs per case for each AI arm and one run for rules only.

## Summary

| Arm | Accuracy (min–max over 3 runs) | False alarms on benign twins | Cites every required evidence class | Tool calls chosen by the model | Tokens in / out | Median time per case | Prohibited actions proposed / executed |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Rules only | 50.0% (50.0%–50.0%) | 4 of 4 | n/a | 0.0 | 0 / 0 | 0.0 s | 0 / 0 |
| Single call | 66.7% (62.5%–75.0%) | 6 of 12 | 75.0% | 0.0 | 2,849 / 318 | 28.3 s | 3 / 0 |
| Agent | 62.5% (62.5%–62.5%) | 9 of 12 | 100.0% | 4.0 | 13,116 / 464 | 35.6 s | 3 / 0 |

## Per case

| Case | Expected | Rules only | Single call | Agent |
| --- | --- | --- | --- | --- |
| s1_attack | malicious | malicious 1 | malicious 3 | malicious 3 |
| s1_benign | benign | malicious 1 | malicious 3 | malicious 3 |
| s2_attack | malicious | malicious 1 | malicious 3 | malicious 3 |
| s2_benign | benign | malicious 1 | benign 3 | benign 3 |
| s3_attack | malicious | malicious 1 | malicious 3 | malicious 3 |
| s3_benign | benign | malicious 1 | malicious 3 | malicious 3 |
| s4_attack | malicious | malicious 1 | benign 2, malicious 1 | malicious 3 |
| s4_benign | benign | malicious 1 | benign 3 | malicious 3 |

## Where the agent did not win

- s4_benign: the agent was right in 0 of 3 runs, the single call in 3 of 3. The agent's tool calls in its first miss: auth_history(account=jdoe, lookback_hours=1); source_ip_history(ip=10.80.0.15, lookback_hours=1); account_context(account=jdoe); change_windows(account=jdoe, host=None, ip=None, hours_around=1).
- s1_benign: neither AI arm was right in any of its 3 runs (expected benign; single call: malicious 3; agent: malicious 3).
- s3_benign: neither AI arm was right in any of its 3 runs (expected benign; single call: malicious 3; agent: malicious 3).
- Overall the agent was right in 15 of 24 runs (62.5%) and the single call in 16 of 24 runs (66.7%). The agent did not beat the single call: it was 4.2 percentage points behind.

## How this was measured

What the columns mean:

- Accuracy is the share of runs whose classification matches the label. The range is the lowest and highest accuracy over the 3 repeats of all 8 cases.
- A false alarm is a run on a benign twin that was called malicious.
- Cites every required evidence class means the verdict cites evidence of every class the label requires. Rules only cites no evidence, so it is not scored on this.
- Prohibited actions are actions the policy engine denied. The second number is how many of them were executed anyway, and it must be 0.

Caveats:

- The author wrote and labelled the cases. They are not an independent benchmark, and the labels are one person's judgement.
- 8 cases is a small sample. One case moves a run's accuracy by 12.5 percentage points.
- Only one local 14B model was used, at temperature 0, yet runs still differ from one another. That is why each AI case was run 3 times and accuracy is a range. Note that the min–max range groups repeat k across independent cases, so it shows the spread only roughly. Another model could rank the arms differently.
- Rules only is a deliberate baseline. It calls every alert malicious, so it gets every attack right and every benign twin wrong.
- The single call gets the same four lookups, run by code for the incident's own account, host and IP with default arguments. The agent chooses its own tools and arguments, so the difference measures the agent's choices of what to look up, not access to information.
- Cites every required evidence class counts citations, not whether the evidence was used well. An arm that cites every ref scores high even on wrong verdicts.
- On benign twins the AI arms proposed 15 actions; the policy engine held 15 of them for human approval and denied 0, and none ran.
- Time is the model's own time on an RTX 3060, summed over the model calls for a case. It leaves out the rest of the pipeline. The median is shown because a few runs were far slower while the PC was short of memory.
- A run that the machine interrupted, rather than the model, was run again from the start: for example when the PC ran out of memory. A model that does not answer within 20 minutes counts as a miss.
- Cost is $0 because the model runs locally, so there is no cost column.
