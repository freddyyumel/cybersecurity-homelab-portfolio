# Detection and investigation searches

These searches reflect the lab's `index=windows`, `host=DC01`, `XmlWinEventLog:Security` fields and the `SecurityEvent` Log Analytics table. Adapt host names, field mappings, time filters and log sources to your own environment.

- **01-group-additions.spl** — find group additions (Event ID 4728)
- **02-group-removals.spl** — find group removals (Event ID 4729)
- **03-authentication-review.spl** — search DC01 4624/4672 for the account string; zero matches are *not* definitive proof of no logon
- **04-kerberos-focused-hunt.kql** — focus on the Oct 29 UTC window; includes Event IDs 4771, 4768, 4624, although screenshot results show only 4771

For a more complete production investigation, review event XML, SIDs and logon IDs, tune the time range and consult additional authentication and endpoint telemetry. The provided SPL and KQL files are investigative searches, not production-ready detection rules.
