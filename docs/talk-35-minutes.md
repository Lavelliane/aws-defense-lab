# Cloud Defense Lab: From AWS Attack to Wazuh Alert

Presenter: Jhury Kevin Lastre

Prepare by running the lab before the event. Present screenshots and short recorded clips; no live deployment is required.

| Minutes | Slides | Story and evidence |
|---|---|---|
| 0–3 | 1–2 | Show the synthetic confidential file and ask who accessed it. Explain the lab objective. |
| 3–8 | 3–4 | Architecture and the authorization/IAM weaknesses. Terraform is the builder; Wazuh is the observer. |
| 8–14 | 5–6 | Recorded probe and restricted export. Show that the request returned HTTP 200 in vulnerable mode. |
| 14–21 | 7–9 | App event → S3 request ID → CloudTrail identity → Wazuh alert. Explain the difference between web source and AWS role. |
| 21–26 | 10–11 | Show the synthetic IOC entry and enriched rule. Unknown-IP behavior still alerts. An IOC match adds context, not proof. |
| 26–31 | 12–13 | Harden authorization and IAM. Repeat request: HTTP 403. Independently verify S3 AccessDenied and its CloudTrail record. |
| 31–35 | 14 | Three lessons and questions. Understand the failure, collect both telemetry sources, verify prevention. |

## Capture checklist

- [ ] Architecture diagram and narrow app-role policy (before/after).
- [ ] Vulnerable app response, showing only synthetic CSV data.
- [ ] Wazuh alert 110012 with run ID, source IP and object key.
- [ ] Corresponding CloudTrail GetObject with exact matching request ID; redact account ID.
- [ ] Indicator list clearly labelled **synthetic lab IOC**.
- [ ] Hardened response HTTP 403 and Wazuh 110013.
- [ ] Independent role permission check and CloudTrail AccessDenied (110031).
- [ ] Two short clips, each 30–60 seconds; retain screenshots as playback backup.

Do not show passwords, tokens, raw Terraform state, full SSM installation output, personal AWS account details or unredacted unrelated management events. No screenshots or recordings in `evidence/` should be described as real until captured from your deployed lab.

## Questions to prepare for

**Does Wazuh stop the attack?** These rules detect and enrich. Application authorization and IAM prevent the demonstrated access. No automatic IP blocking is configured.

**Why do we need application logs if we have CloudTrail?** CloudTrail shows the AWS principal. The application log shows the web request and its original socket source.

**Why not wait live for CloudTrail?** Delivery is asynchronous and typically averages several minutes, plus Wazuh polling. This talk is about the evidence, not delivery latency.

**Is the attacker IP really malicious?** No. It is an owned manager address seeded as a synthetic indicator so the matching behavior is reproducible.

**Is this production-ready?** No. It deliberately exposes a narrow authorization flaw, uses a lab HTTP endpoint and a single monitoring host. The code and automation are a reusable teaching testbed.
