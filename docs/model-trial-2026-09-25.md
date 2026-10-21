# Model trial, 2026-09-25

Open-weight models served by Ollama 0.34.4 on a standard GitHub-hosted runner (4 CPUs, 16 GB
RAM), temperature 0, run by the `Model trial` workflow. Two hand-labelled cases: the S1 attack
(expected malicious) and its benign twin (expected benign). Two cases is a smoke test, not an
evaluation.

| Model | S1 attack | Benign twin | Both cases |
|---|---|---|---|
| `qwen3:8b` | malicious ✅ | malicious ❌ | ~8.5 min |
| `qwen3:8b`, thinking on | malicious ✅ | inconclusive ⚠️ | ~14 min |
| `qwen3:14b` | malicious ✅ | benign ✅ | ~15.5 min |

What happened:

- **`qwen3:8b`**: its first live run exposed a tool bug. The model asked for 24 hours of history,
  the backup account's previous nightly login fell just outside that window, and the tool
  reported the backup host as never seen before. The fix makes the known-source baseline always
  cover 30 days. With correct evidence the model still called the benign twin malicious, reading
  "this source is one the account normally uses" as "a persistent threat".
- **`qwen3:8b` with thinking on**: on the benign twin it skipped the tool entirely. It declared
  the case malicious, claimed there was no prior login history, and cited evidence it never
  collected. The agent rejected that output (a malicious verdict must cite evidence it actually
  gathered) and fell back to inconclusive with no actions.
- **`qwen3:14b`**: correct on both, with reasoning grounded in the evidence. On the benign twin
  it noted the source was known and used successfully in the past, and proposed no actions.

In every case the policy engine required human approval before `disable_account` could run, so
no wrong verdict could have locked an account on its own.

Decision: the live demo uses `qwen3:14b` with thinking off.
