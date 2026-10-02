# PC verdict accuracy

Model: ollama:qwen3:14b

**1 of 10 labelled incidents matched. See How this was measured for what this number does and does not show.**

| Incident | First alert | Expected | Actual | Confidence | Tools used | Result |
| --- | --- | --- | --- | --- | --- | --- |
| Host-based anomaly detection event (rootcheck). on my-pc | 2026-09-29T15:14:54.862000+00:00 | benign | inconclusive | 0.30 | rule_context, process_activity, host_posture, related_alerts | miss |
| Host-based anomaly detection event (rootcheck). on my-pc | 2026-09-29T03:14:48.346000+00:00 | benign | inconclusive | 0.40 | rule_context, process_activity, host_posture, related_alerts, auth_history | miss |
| Windows application error event. on my-pc | 2026-09-28T23:50:49.685000+00:00 | benign | inconclusive | 0.30 | rule_context, process_activity, host_posture | miss |
| User account changed on my-pc | 2026-09-28T20:28:00.935000+00:00 | benign | inconclusive | 0.40 | rule_context, auth_history, process_activity, related_alerts | miss |
| SessionEnv was unavailable to handle a critical notification event. on my-pc | 2026-09-28T20:27:52.370000+00:00 | benign | inconclusive | 0.30 | rule_context, process_activity, related_alerts | miss |
| Multiple Windows Logon Failures on my-pc | 2026-09-28T15:34:15.084000+00:00 | benign | benign | 0.60 | rule_context, auth_history, related_alerts, process_activity | match |
| User account changed on my-pc | 2026-09-28T15:14:43.780000+00:00 | benign | inconclusive | 0.50 | rule_context, auth_history, process_activity, related_alerts | miss |
| Host-based anomaly detection event (rootcheck). on my-pc | 2026-09-28T15:14:42.453000+00:00 | benign | inconclusive | 0.40 | rule_context, related_alerts, process_activity, auth_history | miss |
| SessionEnv was unavailable to handle a critical notification event. on my-pc | 2026-09-28T15:14:40.079000+00:00 | benign | inconclusive | 0.30 | rule_context, related_alerts, process_activity | miss |
| Host-based anomaly detection event (rootcheck). on my-pc | 2026-09-27T23:17:48.761000+00:00 | benign | inconclusive | 0.30 | rule_context, related_alerts, process_activity, auth_history | miss |

## Why the owner expected each verdict

- **Host-based anomaly detection event (rootcheck). on my-pc** (2026-09-29T15:14:54.862000+00:00): Wazuh's rootcheck flags an alternate data stream on C:\WINDOWS\tracing. Windows creates it itself, and this is a known rootcheck false positive. It fires on every 12-hour scan.
- **Host-based anomaly detection event (rootcheck). on my-pc** (2026-09-29T03:14:48.346000+00:00): The same C:\WINDOWS\tracing alternate data stream, found again by the scheduled 12-hour rootcheck scan.
- **Windows application error event. on my-pc** (2026-09-28T23:50:49.685000+00:00): tail.exe from Git for Windows stopped responding. It was running as part of the coding assistant's shell commands on the PC at that time.
- **User account changed on my-pc** (2026-09-28T20:28:00.935000+00:00): SYSTEM, not a person, updated the owner's local account at sign-in, and nothing else happened around it. The owner does not recall changing the account, so this is the likely benign explanation rather than a confirmed one.
- **SessionEnv was unavailable to handle a critical notification event. on my-pc** (2026-09-28T20:27:52.370000+00:00): Startup noise: the Remote Desktop configuration service was not ready when Winlogon sent a notification, at the same moment as the sign-in.
- **Multiple Windows Logon Failures on my-pc** (2026-09-28T15:34:15.084000+00:00): The owner's own test: failed sign-ins for sentinel-test-nobody, an account that does not exist, made on purpose to check the pipeline.
- **User account changed on my-pc** (2026-09-28T15:14:43.780000+00:00): SYSTEM updated the owner's local account at sign-in, with nothing else around it. The owner does not recall changing the account.
- **Host-based anomaly detection event (rootcheck). on my-pc** (2026-09-28T15:14:42.453000+00:00): The C:\WINDOWS\tracing alternate data stream again, a known rootcheck false positive.
- **SessionEnv was unavailable to handle a critical notification event. on my-pc** (2026-09-28T15:14:40.079000+00:00): Startup noise from the Remote Desktop configuration service at sign-in.
- **Host-based anomaly detection event (rootcheck). on my-pc** (2026-09-27T23:17:48.761000+00:00): The C:\WINDOWS\tracing alternate data stream, found by the first rootcheck scans after Wazuh was installed.

## How this was measured

The expected classification of each labelled incident was set by the owner, who knew what happened on the PC. The owner is also the author of this project, so these are one person's judgements. An incident counts as a match only when the model's classification equals the label. Incidents without a label are listed but not scored. With 10 labelled incidents this number is anecdotal: it shows how the model did on these cases, not how often it is right in general.

## Fix steps

- Recommendations: 10
- Steps: 53
- Dropped steps: 0 (removed by the checker for weakening the PC, linking to a site that is not on the allow-list, being too long, or going over the step limit)
- 6 of 8 recommendations with a version bound name a version at least that new in their steps.
- 2 recommendations have no version bound to check.

The version bound is worked out again from the weak spots kept in this sample, which can be fewer than the program has, so a step passes when it names a version at least as new as that bound. The check only looks for such a version number in a step, not whether the step is right.
