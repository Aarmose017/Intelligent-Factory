# Response Layer Threats

The response layer receives alerts from the detector, applies a policy rule, and picks an action tier. Anyone who can interfere with it can defeat the whole slice without touching the factory. This page covers four ways that could happen, what the weakness is, and what we would do about it.

Items marked **[verify]** depend on how the current code behaves and should be confirmed before presenting.

---

## 1. Tampering with `policy/policy.yaml`

**Weakness.** The policy file decides which tier each alert gets. Whoever can edit it controls the response. Changing one rule's tier lets an attacker:

- **Downgrade** a dangerous incident class to tier 0 or a low tier, so a real attack gets logged but not acted on. This is silent and hard to notice.
- **Upgrade** a common benign class to a high tier, so the line keeps tripping into safe mode.

Edit access exists at two levels: write access to the GitHub repo (any collaborator), and write access to the file on the machine running the service. The service also loads the file without checking where it came from or whether it was changed.

**What we would do.**
- Require review on any change under `policy/` (CODEOWNERS plus the existing pull request rule), so no single person can change a tier alone.
- Make the file read-only for the account the service runs under.
- Validate on load: only known tiers allowed, and every critical incident class must still have a rule.
- Log a hash of the policy at startup and include the policy version in every decision, so a change shows up in the record.

*Lands in Sprint 3 except the review rule, which we can enable now.*

---

## 2. Killing the process

**Weakness.** If the receiver stops, no alerts get a decision. What happens next depends on the failure mode:

- **Fail-open:** the line keeps running with no protection. An attacker who can stop the process, or just crash it with bad input, has switched our defence off. **[verify: does the line keep running when our layer is down?]**
- **Fail-closed:** the line stops. Safe, but then killing the process is a denial of service.

The service also runs as a single process with no supervisor, and the guide shows no authentication on the endpoint, so anything that can reach the port can talk to it.

**What we would do.**
- Run it under a supervisor that restarts it automatically.
- Add a heartbeat checked by something outside the process, so downtime raises an alarm instead of going unnoticed.
- Decide the failure mode deliberately and write it down. The likely answer is fail-closed for the highest-risk classes with a human alert, which needs a team decision.
- Bind the service to an internal interface only and restrict who can reach it.

*Failure-mode decision now, supervisor and heartbeat in Sprint 3.*

---

## 3. False alerts used to force safe mode

**Weakness.** This turns our own defence into the attack. If an attacker can send alerts to the receiver, or fool the detector into producing them, they can trigger a high tier on demand and stop the line repeatedly. Today:

- The endpoint has no authentication, so anyone who can reach it can pose as the detector.
- There is no rate limit and no check for repeated or replayed alerts.
- A single alert with a high enough confidence can reach a high tier on its own.

Schema validation (Part 3, item 1) helps with malformed input but not with well-formed fake alerts.

**What we would do.**
- Authenticate the sender, for example a shared secret or HMAC signature on each alert.
- Reject duplicate `alert_id` values and alerts whose timestamps are stale, to stop replays.
- Rate limit per source.
- For the highest tiers, require corroboration (several alerts in a time window, or human confirmation) rather than one message.

**Tradeoff to state when presenting.** Every one of these slows the response to a real attack. The more we demand before escalating, the more time a real attacker gets. We should say which side we chose and why.

*Authentication and rate limiting in Sprint 3.*

---

## 4. Tampering with the log

**Weakness.** `logs/response.jsonl` is a plain file we append to. Anyone with write access to it can:

- Edit or delete lines to hide that an attack, or a bad policy change, ever happened.
- Fabricate lines to blame something else.

Separately, the log records fields taken from incoming alerts. If those are written unsafely, an attacker can shape what appears in the log.

**What we would do.**
- Chain the entries: each line carries a hash of the previous line, so any edit or deletion breaks the chain and can be detected.
- Copy the log off the machine as it is written (a remote or write-once location), so deleting the local file does not erase the evidence.
- Restrict file permissions so only the service can append.
- Always write entries with a JSON serialiser rather than string formatting, and log rejected alerts too so bad input is visible.

*Hash chaining and off-machine copy in Sprint 3.*

---

## Summary

| Threat | What the attacker gains | First fix |
|---|---|---|
| Policy edit | Silent downgrade or forced safe mode | Required review on `policy/`, validation on load |
| Kill the process | Line unprotected or stopped | Decide fail-open vs fail-closed, add supervisor and heartbeat |
| False alerts | Denial of service via our own defence | Authenticated alerts, replay and rate checks |
| Log tampering | Evidence erased or forged | Hash-chained entries, off-machine copy |
