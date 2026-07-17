# Offensive Lab Targets

Intentionally vulnerable local-lab targets for the **offensive** module. Every
service listed here binds **only to 127.0.0.1** — there is no
`0.0.0.0:` published port in any of these compose files, by construction.

The scope guard in `offensive.scope_guard` will refuse any attack attempt
against a host that is not registered via `guardscope labs register`. So once
you `docker compose up` one of these targets, register it:

```bash
guardscope labs register --name juice-shop --host 127.0.0.1 --port 13000 --description "OWASP Juice Shop (intentionally vulnerable)"
```

## Layout

| Subdir | Contents |
|---|---|
| `compose/` | One `docker-compose.yml` per active lab target, all loopback-only. |
| `compose.disabled/` | Recipes for targets we tried but couldn't bring up in this environment (currently: vuln-node — the ghcr.io image is access-controlled). |
| `registers/` | Pre-canned `guardscope labs register` invocations as shell scripts. |

## Available targets

| Target | Compose file | Bind | Use for |
|---|---|---|---|
| OWASP Juice Shop | `compose/juice-shop.yml` | `127.0.0.1:13000` | Modern web app vulns (XSS, SQLi, broken auth, NoSQLi, JWT abuse) |
| DVWA | `compose/dvwa.yml` | `127.0.0.1:8081` | Classic PHP vulnerabilities, low-friction training |
| ~~Vulnerable Node App~~ | `compose.disabled/vuln-node.yml.unavailable` | — | Parked; source image on ghcr.io returns 401. |

## Port collision policy

When a target port is already bound on the host (for example, the PentAGI
Next UI uses `0.0.0.0:3000`), the compose file maps the **container** port to
an alternate **host** loopback port. The registered `guardscope labs
register` invocation matches the alternate port — frontends and the scope
guard both see the same host-port pair.

## Why bother with a registry?

Because the scope guard refuses anything not registered — including the
default `localhost` lab created by `guardscope demo`. Registering each
target individually is intentional friction that prevents the operator from
pointing the offensive wrappers at a host they did not set up on purpose.
