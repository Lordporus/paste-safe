# Security Policy

`paste-safe` handles secrets, so reports are welcome and taken seriously.

## Supported versions

The latest published minor version receives fixes.

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") on this repository.

Include:

- what is leaked, missed, or restored incorrectly,
- a minimal input that reproduces it (mask the real secret),
- your OS, Node version, and `paste-safe --version`.

## Scope

In scope: detection bypasses, partial redactions that leave secret fragments, vault
permission or expiry bugs, and `restore` substituting the wrong value.

Out of scope: formats the README says are not detected (IPv6, JSON-style `"key": "value"`),
and secrets that are already public.
