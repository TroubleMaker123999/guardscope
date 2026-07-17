"""GuardScope offensive tooling — tightly scoped local-lab operations only.

This subpackage wraps external security tools (Nmap, Hydra, sqlmap, Nuclei) so
that we can drive them programmatically **against explicitly registered local
lab targets**. Every wrapper funnels through ``scope_guard.assert_authorized``
before invoking the underlying binary, and every invocation is recorded in the
audit log.

Hard rules enforced here:

  * Targets MUST resolve to a loopback address (localhost / 127.0.0.0/8 / ::1).
  * Targets MUST be present in the registered lab whitelist.
  * No persistence, no stealth, no anonymous/public-target operation.
  * No exploit payload generation; only standard CLI flags of each tool.

If you are reading this and the safety constraints surprise you, read
``LEGAL.md`` at the repository root first.
"""
