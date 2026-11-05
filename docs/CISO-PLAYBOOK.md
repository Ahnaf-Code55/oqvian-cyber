# OQVIAN CISO playbook

Ready-to-run prompts for the work a CISO actually does. Each one names the model
to pick in the harness, the tools OQVIAN will call, and what the output should
look like. Paste the prompt as-is — the agent instructions make it retrieve from
the local knowledge base before answering.

Replace the bracketed parts. Everything runs offline.

---

## 1. Morning exposure check

**Model:** `oqvian-ciso` · **Tools:** `kb` (kev, cve)

```
We run [product/version list]. Search the CISA KEV catalogue for vulnerabilities
in those products added in the last 30 days. For each: CVE, product, date added,
known ransomware use, and the single action that removes the exposure. Rank by
what an attacker would actually use against us, not by CVSS. If a product shows
no KEV entries, say that instead of guessing.
```

Why it works: `kb(action="kev")` searches the local 1,768-entry KEV catalogue, so
"not affected" is a real answer rather than a hallucination.

---

## 2. Board one-pager

**Model:** `oqvian-ciso` · **Tools:** `kb` (search)

```
Write a board update on [topic: e.g. ransomware exposure / MFA rollout / third
party breach]. Structure: decision needed (one sentence), three options with
cost and residual risk, recommendation with confidence, and what would change my
mind. Under 400 words, no acronyms without a gloss. Map the recommendation to
NIST CSF 2.0 functions and name the ISO 27001:2022 Annex A control IDs.
```

---

## 3. Compliance mapping without a consultant

**Model:** `oqvian-ciso` · **Tools:** `kb` (search, attack)

```
Map our current controls to NIST 800-53 Rev 5 for the [AC, AU, IR, SC] families.
For each control: implemented / partial / gap, the evidence we would need to
prove it, and the cheapest credible way to close a gap. Output a table sorted by
gap severity. Cite the control ID for every row.
```

Then, for the gaps that turn into engineering work:

```
For the partial controls above, give the concrete configuration change and the
command that verifies it. Prefer what we can automate.
```

---

## 4. CVE triage that survives scrutiny

**Model:** `oqvian-defensive` · **Tools:** `kb` (cve, kev, detection)

```
Triage CVE-[id]. Give me: CVSS and vector, whether it is in KEV and since when,
the affected and fixed versions, the preconditions an attacker needs, whether it
is reachable from the internet in a default deployment, and the detection that
would catch exploitation. End with one of: patch now, patch this sprint, accept
with compensating control, not applicable — and justify it in two sentences.
```

---

## 5. Detection engineering, end to end

**Model:** `oqvian-defensive` · **Tools:** `kb` (detection, atomic, attack)

```
Write a Sigma rule for [behaviour, e.g. LSASS access via comsvcs.dll MiniDump].
Include title, id, status experimental, description, logsource, detection with a
condition, falsepositives, level and ATT&CK tags. Then give the Atomic Red Team
test that proves it fires, the Sysmon/Windows event IDs the rule depends on, and
three ways an attacker could evade it. Finally write the Sentinel KQL version.
```

The `kb(action="atomic")` lookup returns the real test IDs, so you get a
validation step, not a suggestion.

---

## 6. First hour of an incident

**Model:** `oqvian-ir` · **Tools:** `kb` (attack, detection)

```
We have [alert: e.g. EDR flagged Cobalt Strike beacon on FIN-LAPTOP-14]. Give me
the first hour: containment decision and who authorises it, evidence to preserve
in volatility order with the exact command for each artefact, the ATT&CK
techniques to hunt for, and the three questions that decide whether this is
contained or spreading. One-paragraph executive summary, then a technical
timeline skeleton. Do not recommend cleanup before evidence preservation.
```

Escalate to a full timeline with:

```
Build the investigation plan: every log source, what to query, what a benign
explanation looks like, and the pivot that confirms or kills the hypothesis.
```

---

## 7. External attack surface review

**Model:** `oqvian-offensive` · **Tools:** `recon`, `execute`

> Only after adding the domain to `~/.config/oqvian/scope.json`.

```
Passive first: enumerate certificate-transparency subdomains for [domain], then
probe each for HTTP status, server header, TLS version and certificate expiry.
Report anything internet-facing that should not be: admin panels, staging
hostnames, expired certificates, TLS below 1.2, missing HSTS/CSP. Do not scan
ports until I approve the list.
```

Then, on approval:

```
Scan the approved hosts for the top 200 TCP ports with service detection, and
run nuclei with severity critical,high only. Rate-limit to something that will
not trip an IDS. Summarise findings by host with the evidence line for each.
```

Every call is scope-checked and appended to
`~/.local/share/oqvian/audit.jsonl` — attach that log to the report.

---

## 8. Third-party / vendor risk

**Model:** `oqvian-ciso` · **Tools:** `kb` (search)

```
Assess [vendor] from this evidence: [SOC 2 report summary / questionnaire
answers]. Score them on: data access breadth, breach history, incident
notification SLA, subprocessor transparency, encryption and key management,
exit/portability. Give a risk rating with the two findings that drive it, and the
three contract clauses I should insist on.
```

---

## 9. Purple-team exercise design

**Model:** `oqvian-offensive` · **Tools:** `kb` (attack, atomic, detection), `execute`

```
Design a two-day purple-team exercise against [scenario: e.g. initial access via
phishing to domain admin]. For each step: ATT&CK technique, the red action with
its exact command, the blue detection that should fire with the Sigma rule or
log source, and the expected time to detect. Include the stop condition and the
deconfliction contact. No action outside the scope file.
```

---

## 10. Metrics the board will actually read

**Model:** `oqvian-ciso`

```
Turn these raw numbers into four metrics a board can act on: [MTTD, MTTR, patch
SLA compliance, phishing failure rate, KEV count, open criticals]. For each:
current value, trend, the decision it should trigger, and the threshold at which
it becomes a board item. Reject any metric that cannot change a decision.
```

---

## 11. Policy and exception writing

**Model:** `oqvian-ciso` · **Tools:** `kb` (search)

```
Draft a [cloud usage / AI tool usage / privileged access] policy: scope, the
rule, the exception process with owner and expiry, the evidence we collect, and
how we test compliance. Map each clause to ISO 27001:2022 Annex A and NIST CSF
2.0. Keep it under two pages and write it so a non-technical reader can follow
the rule and an auditor can test it.
```

---

## 12. What did we learn

**Model:** `oqvian-ir`

```
Post-incident review for [incident]. Separate what happened from what we believed
happened. Give: root cause (technical and organisational), the three controls
that failed, the two that worked, and five corrective actions with owner, cost,
and the date each becomes overdue. No blame language, no generic "improve
training".
```

---

## Operating habits

- **Pick the role model, not the general one.** The system prompts differ enough
  to change output shape: `oqvian-ciso` gives you decision framing, `oqvian-defensive`
  gives you rule syntax, `oqvian-ir` gives you phase structure.
- **Ask for the reference ID.** If the answer has no `T####`, `CVE-`, `CWE-` or
  rule title, the model did not retrieve — treat the answer as unverified.
- **One decision per session.** The 16K context is real; long sessions lose the
  early constraints. Start fresh for a new decision.
- **Keep the audit log with the report.** `scope.json` plus `audit.jsonl` is the
  rules-of-engagement evidence for an authorised test.
- **The model drafts, you sign.** Nothing here is a decision until a human makes
  it.
