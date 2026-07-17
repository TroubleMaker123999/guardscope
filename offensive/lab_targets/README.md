# Offensive Lab Targets

Intentionally vulnerable local-lab targets for the **offensive** module. Every
service listed here binds **only to 127.0.0.1** — there is no
`0.0.0.0:` published port in any of these compose files, by construction.

The scope guard in `offensive.scope_guard` will refuse any attack attempt
against a host that is not registered via `guardscope labs register`. So once
you `docker compose up` one of these targets, register it:

```bash
guardscope labs register --name juice-shop --host 127.0.0.1 --port 3000 --description "OWASP Juice Shop (intentionally vulnerable)"
```

## Layout

| Subdir | Contents |
|---|---|
| `compose/` | One `docker-compose.yml` per lab target, all loopback-only. |
| `registers/` | Pre-canned `guardscope labs register` invocations as shell scripts. |

## Available targets

| Target | Compose file | Bind | Use for |
|---|---|---|---|
| OWASP Juice Shop | `compose/juice-shop.yml` | `127.0.0.1:3000` | Modern web app vulns (XSS, SQLi, broken auth, NoSQLi, JWT abuse) |
| DVWA | `compose/dvwa.yml` | `127.0.0.1:8081` | Classic PHP vulnerabilities, low-friction training |
| Vulnerable Node App | `compose/vuln-node.yml` | `127.0.0.1:3001` | Express.js prototype pollution / SSRF |

## Why bother with a registry?

Because the scope guard refuses anything not registered — including the
default `localhost` lab created by `guardscope demo`. Registering each
target individually is intentional friction that prevents the operator from
pointing the offensive wrappers at a host they did not set up on purpose.
