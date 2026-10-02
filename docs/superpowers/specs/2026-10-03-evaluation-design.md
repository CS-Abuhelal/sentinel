# Evaluation: does the tool-using agent beat a single AI call? (design)

Date: 2026-10-03. Branch: `feat/evaluation`, stacked on `feat/wazuh-report-sample` (PR #14).

## Goal

Answer the question in `CLAUDE.md` honestly, on hand-labelled lab cases: does an adaptive,
tool-using agent investigate better than a single-shot LLM given the same information, and
better than rules alone? Report the result in `docs/eval-results.md` and a README table,
including where the agent does not win.

## Decisions (agreed with Ahmed, 2026-10-03)

- **Cases.** 8 cases in 4 attack/benign pairs (the 2 existing + 6 new).
- **Tools.** 3 new read-only agent tools.
- **Arms.** 3: rules-only, single AI call with the full evidence bundle, agent with tools.
- **Model and repeats.** Local `qwen3:14b`, 3 runs per case for each AI arm (48 AI runs).
  Every run is recorded. CI replays the recordings and never calls a model.

## Cases

Every case is a static `auth.log` written by hand, with a hand-labelled `scenario.yml`. They
use made-up accounts and private or documentation IP ranges. No attack traffic is generated or
run. Every case must trip the existing brute-force rule (10 or more failed SSH passwords for
one account from one source within 10 minutes) and produce exactly one incident. So the arms
all start from the same alert, and the only difference between them is how well they explain
it.

| Case | Expected | Story | What separates it from its twin |
|---|---|---|---|
| `s1_attack` (exists) | malicious | 24 failures for `jdoe` from a never-seen IP, then success | the source is not one `jdoe` uses |
| `s1_benign` (exists) | benign | backup job retrying a stale password from its usual host | the source is the account's usual host |
| `s2_attack` | malicious | 15 failures for the privileged `labadmin` from a new external IP; no success | privileged target, unknown source, no change |
| `s2_benign` | benign | `svc_deploy` failing from the CI runner during a scheduled credential rotation | a change window covers the account and host |
| `s3_attack` | malicious | one IP tries several accounts, crosses the threshold on `msmith`, then gets into `msmith` | the IP touched many accounts |
| `s3_benign` | benign | a saved-credential app on `msmith`'s own workstation retries an old password after a password change, then stops | one account, the user's usual workstation |
| `s4_attack` | malicious | night-time failures then success for `jdoe` from an unknown IP, no change on record | unknown source, no explanation |
| `s4_benign` | benign | failures then success for `jdoe` from a new IP during a documented VPN egress change | a change window covers the new IP |

Each `scenario.yml` also lists `required_evidence`: the evidence classes a correct verdict must
cite. Examples: `auth_history` for S1, `change_window` for the S2 and S4 twins,
`entity_context` for S2, and `auth_history` plus `network_activity` for S3.

## Contracts 1.8.0 (D-17)

- `ChangeWindow`: `change_id`, `title`, `start`, `end`, `accounts`, `hosts`, `source_ips`,
  `description`.
- `Scenario` gains `required_evidence: list[EvidenceClass] = []` and
  `changes: list[ChangeWindow] = []`. The change calendar lives with the case, in
  `scenario.yml`, so each case is self-contained. The agent never sees the expected
  classification: `Scenario` is already never shown to the agent, and only `changes` reach a
  tool.
- `Inventory` gains the accounts and hosts the new cases use: `svc_deploy`, `msmith`,
  `ci-runner-01` and `ws-msmith`.

Follow the usual steps: models, version bump, fixtures, `npm run gen:types`, DECISIONS entry.

## New tools (`agent/tools/`)

`ToolContext` gains `inventory: Inventory | None` and `changes: list[ChangeWindow]`.

- **`account_context(account)`** returns the role, `privileged`, `protected` and whether the
  account is known. Evidence class: `entity_context`.
- **`source_ip_history(ip, lookback_hours=168)`** returns every account the IP tried, with
  failures and successes per account, and first and last seen. Evidence class:
  `network_activity`.
- **`change_windows(account?, host?, ip?, hours_around=24)`** returns the change windows that
  overlap the incident window (plus or minus `hours_around`) and mention the account, host or
  IP. Evidence class: `change_window`.

`TOOLS` (the lab agent) becomes `auth_history` plus these three. The system prompt gains one
line on checking for a documented change before calling something malicious. The cap of 6 tool
calls stays.

## Arms

1. **A1, rules only** (`eval/arms.py`). The brute-force rule fired, so the verdict is malicious.
   Confidence comes from the rule level: low 0.4, medium 0.6, high 0.8, critical 0.9. It cites
   no evidence and proposes no actions. This is
   the deterministic baseline. It is expected to fail every benign twin, which is what the twins
   are for.
2. **A2b, single AI call with full context** (`agent/single_shot.py`).
   - Code first runs each of the 4 tools once with the incident's own account, host and source
     IP, then pastes all 4 results as refs E1 to E4 into one prompt with no tools.
   - The model must answer in the same verdict JSON as the agent, citing the refs.
   - It reuses the agent's draft parsing and `Verdict` building, with
     `arm=A2B_FULL_CONTEXT` and `tool_calls_made=0`.
3. **A3, the agent with tools.** This is the existing `investigate()` with the 4 tools.

Both AI arms run the normal response path: deterministic risk score, policy engine, and the
executor in dry-run mode. `pipeline.run.run_incident` gains an `investigator` parameter that
defaults to `investigate`, so the eval reuses the real pipeline instead of copying it.

## Metrics

**Per run** (case × arm × repeat):
- the classification, and whether it matches `expected_classification`;
- the confidence;
- a false positive (a benign case called malicious);
- whether the verdict cites at least one evidence item of each `required_evidence` class;
- tool calls;
- input and output tokens;
- latency;
- prohibited actions proposed (actions the policy engine denies);
- prohibited actions executed (denied actions that ran). This must be 0.

**Tokens.** The Ollama client records `prompt_eval_count` and `eval_count` on each response and
sums them into the verdict. Recordings store them, so replay reports the real numbers. Cost is
$0: the model runs locally. The report says so and does not invent API prices.

**Per arm:**
- accuracy as the mean over runs, with the minimum and maximum over the 3 repeats;
- false positives on benign twins;
- the rate at which required evidence was cited;
- the means of tool calls, tokens and latency;
- the totals of prohibited actions proposed and executed.

## Running it

- `python -m eval.run --llm ollama --repeats 3 --record-dir eval/recordings` runs the 8 cases
  live. It writes one recording per case, AI arm and repeat
  (`eval/recordings/<case>.<arm>.<n>.json`) and the results.
- `python -m eval.run` (default: replay) rebuilds every run from the recordings, then writes
  `eval/results.json` (the per-run rows) and `docs/eval-results.md`.
- A test replays everything and checks that `docs/eval-results.md` matches byte for byte. CI
  needs no model.

## The report (`docs/eval-results.md`)

It has:
- a summary table per arm;
- a per-case table: expected, then each arm's classification over the 3 runs (for example
  `2/3 benign, 1/3 inconclusive`);
- where the agent did not win;
- how it was measured.

The caveats are stated plainly:
- The cases were written and labelled by the author.
- 8 cases is a small set.
- The model is one local 14B model.
- The rules-only arm is a deliberate baseline.
- Single-shot gets the same evidence the agent can ask for, so the test measures adaptivity
  rather than access.

The README gets the summary table.

## Out of scope

The A2a and A2c arms, other models, a dashboard view of the results, the PC sample (it has its
own accuracy report), and paid APIs.

## Testing

- Each new tool has its own tests.
- Every scenario log yields exactly one incident from the brute-force rule, and every
  `scenario.yml` validates.
- Rules-only and single-shot have unit tests with a scripted LLM.
- The metric functions have tests, including the "executed must be 0" check.
- The replay test checks the committed report.
- The existing S1 tests keep passing. The S1 recordings stay valid because the new tools are
  added to the prompt, not swapped for the old one. If a hand-written recording breaks, it is
  re-recorded.

## Risks

- **The AI arms may tie.** Single-shot gets the same evidence, so the arms may be equal. That is
  a valid result, and the report says so.
- **qwen3:14b may stall or return invalid JSON.** That is recorded as `invalid_output` and
  counted as a miss, not retried silently.
- **GPU time.** About 1 hour for 48 runs. The run is resumable, skipping recordings that already
  exist.
