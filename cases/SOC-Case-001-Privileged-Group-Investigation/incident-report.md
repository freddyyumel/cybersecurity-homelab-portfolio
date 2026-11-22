# SOC Analyst Handoff — Case 001

**Case:** Temporary Domain Admin group membership and later Kerberos failures  
**Date of observations:** 29 October 2026, AEDT  
**Environment:** `homelab.test` (authorised home lab)  
**Accounts:** `Sentinel Test` in group-membership logs; `sentinel.test` in authentication logs  
**Priority if unfamiliar in production:** High  
**Lab disposition:** Benign positive — known authorised tests

## What happened

Windows Security Event 4728 on DC01 recorded **Administrator** adding **Sentinel Test** to **Domain Admins** at 21:58:30.980. Event 4729 recorded removal at 22:00:44.374, approximately 2 minutes 13 seconds later. Three Kerberos pre-authentication failures for `sentinel.test` from `192.168.10.20` were observed at 22:06:40, 22:11:43 and 22:12:19. A displayed Splunk search of DC01 Event IDs 4624/4672 for `sentinel.test` returned zero matches over its 30-day range.

## Evidence and significance

| Evidence | Interpretation | Confidence / scope |
|---|---|---|
| DC01 4728/4729 | Privileged group membership was added and then removed | Direct event evidence |
| DC01 4771 via Sentinel | Three failed Kerberos pre-authentication events | Direct event evidence, focused window |
| DC01 4624/4672 search | No string matches for the specified account | Limited to displayed query, host and range |
| Known home-lab testing | Explains the intended account changes and failures | Context from operator, not independently established by logs |

## Assessment

There is **insufficient evidence to establish malicious activity** and **insufficient evidence to prove that no privileged activity occurred**. Short-lived Domain Admin membership can be security-relevant even without matching logon records. Treat as suspicious pending authorisation checks in an unfamiliar environment. Close as **benign positive** only because these events were performed as part of the known authorised lab test.

## Recommended follow-up if this were production

Verify approved change and operator; match account and member SIDs; inspect 4720 and additional group changes; extend authentication and endpoint searches beyond DC01; review for suspicious processes, new services, scheduled tasks and persistence; retain the original events and exact search scope.

**Full investigation, screenshots and queries:** [Case README](README.md)
