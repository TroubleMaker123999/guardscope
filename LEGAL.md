# Legal & Ethics

GuardScope is a **defensive** and **authorization-scoped** tool.

By using GuardScope you agree to the following:

1. **Authorized use only.** You may only target systems you own or have explicit
   written permission to test. GuardScope is intended for use against **local lab
   targets** that the operator has registered in the local lab registry.
2. **No public-target scanning.** GuardScope refuses any verification target whose
   host is not `localhost` or `127.0.0.1`. The default safety gate rejects
   external hosts outright.
3. **No offensive tooling.** GuardScope does not ship exploit payloads, credential
   brute-force modules, authentication bypass primitives, persistence helpers,
   stealth/evasion utilities, or auto-submission features. Built-in parsers
   ingest reports produced by *other* tools (Nmap, OWASP ZAP, SARIF, Bandit,
   Semgrep, Trivy, pip-audit).
4. **Local lab only.** The bundled demo web lab binds exclusively to
   `127.0.0.1`. Do not expose it externally.
5. **No warranty.** GuardScope is provided "as is", without warranty of any kind.
   The authors are not responsible for misuse.

If you do not have authorization to test a system, **do not use GuardScope
against it.**