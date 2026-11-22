# paste-safe

**Redact secrets and PII from your clipboard before you paste logs into an AI chat or a GitHub issue.**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Lordporus/paste-safe/actions/workflows/ci.yml/badge.svg)](https://github.com/Lordporus/paste-safe/actions/workflows/ci.yml)
![Zero Network](https://img.shields.io/badge/network-zero-brightgreen)

![paste-safe demo](./demo.gif)

## Install

```bash
npx paste-safe          # run without installing
npm install -g paste-safe
```

`pnpm dlx paste-safe` and `bunx paste-safe` work the same way.

**Requirements:** Node.js 20 or newer. macOS, Linux, and Windows are supported.

## Quickstart

Copy anything risky, then:

```bash
paste-safe
```

The clipboard is replaced with the sanitized text, and the placeholder → original map is saved so you can undo it. Paste anywhere.

## Before / After

A `.env` file you were about to paste into ChatGPT:

```diff
- DATABASE_URL=postgres://admin:s3cr3t@10.0.0.5:5432/prod
- STRIPE=sk_live_FAKE1234567890ABCD
- SUPPORT_EMAIL=jane.doe@acme.io
+ DATABASE_URL=<DB_URI_1>
+ STRIPE=<STRIPE_KEY_1>
+ SUPPORT_EMAIL=<EMAIL_1>
```

A curl command from a bug report:

```diff
- curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc" \
+ curl -H "Authorization: Bearer <AUTH_TOKEN_1>" \
       https://api.internal/v1/users
```

Changed your mind? Undo it while the vault is alive:

```bash
paste-safe restore
```

Placeholders are numbered across runs (`<EMAIL_1>`, `<EMAIL_2>`, …) and the vault merges them, so every text you sanitized in the last 60 minutes restores correctly. If you paste text the current vault did not produce, `restore` refuses instead of guessing — pass `--force` to override.

## Commands

| Command | What it does |
| --- | --- |
| `paste-safe` | Sanitizes the clipboard (or piped stdin), copies the result back, saves the vault. |
| `paste-safe restore` | Restores placeholders using the local vault. |
| `paste-safe watch` | Polls the clipboard every 500ms and sanitizes secrets in place. |
| `paste-safe clear` | Deletes the local vault immediately. |
| `paste-safe init` | Writes a starter `.paste-saferc.json`. |

## Flags

| Flag | Applies to | Effect |
| --- | --- | --- |
| `--dry-run` | all | Preview detections with masked values; writes nothing, to clipboard or disk. |
| `--no-pii` | all | Redact secrets only; keep emails and IPs. |
| `--no-vault` | all | One-way redaction; never touch disk. |
| `--check` | sanitize | Report only. Never writes the clipboard, stdout, or the vault; exits `1` when anything is detected. |
| `--json` | sanitize | Structured JSON summary (counts + masked previews + the sanitized `output`); stdout stays pure JSON. |
| `--stdin` | all | Force reading stdin and writing stdout. |
| `--force` | `restore` | Restore even if the text was not produced by the current vault. |

Piping is auto-detected, so `cat error.log | paste-safe` just works. In that mode the sanitized text goes to stdout and the summary to stderr, keeping pipelines clean and byte-exact.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. With `--check`, nothing was detected. |
| `1` | With `--check`, something was detected — or the run failed (bad config, no clipboard backend, unreadable vault). |

### Pre-commit example

```bash
git diff --cached | paste-safe --check --no-vault --stdin
```

### Watch mode

```bash
paste-safe watch
```

Every 500ms the clipboard is read, and anything detected is replaced in place, with a timestamped line printed for each change. Ctrl+C stops it. Because each tick launches the platform clipboard helper, `watch` is not free — run it while you work, not permanently.

## What gets detected

| Priority | Rule | Placeholder |
| --- | --- | --- |
| 1 | Private key blocks (`-----BEGIN … PRIVATE KEY-----`) | `<PRIVATE_KEY_N>` |
| 2 | Credentialed DB/broker URIs (postgres, mongodb, redis, mysql, amqp) | `<DB_URI_N>` |
| 3 | AWS keys, GitHub tokens, Stripe keys, OpenAI/Anthropic/DeepSeek `sk-` keys, Google, Slack, Hugging Face, npm | `<AWS_KEY_N>`, `<GITHUB_TOKEN_N>`, … |
| 4 | JWTs | `<JWT_N>` |
| 5 | `Authorization: Bearer` / `Basic` headers (prefix kept) | `<AUTH_TOKEN_N>` |
| 6 | `.env` assignments with `SECRET`/`TOKEN`/`PASSWORD`/`API_KEY`/… (key kept) | `<ENV_SECRET_N>` |
| 7 | Emails and IPv4 addresses | `<EMAIL_N>`, `<IP_N>` |

Higher-priority rules claim their span first, so a database URI containing an IP is redacted once as `<DB_URI_1>` — never re-matched. Identical values reuse the same placeholder within a run.

Known-safe values are ignored: `127.0.0.1`, `0.0.0.0`, `localhost`, semver (`v1.2.3`), `example.com` emails, and obvious placeholders (`YOUR_API_KEY`, `changeme`, `xxx`, `<REDACTED>`).

## Limitations

Detection is regex-based and deliberately conservative. It does **not** catch:

- **IPv6 addresses.**
- **JSON-style pairs** — `"password": "hunter2"` is not matched. `.env`-style `PASSWORD=hunter2` is.
- **Secrets with no recognizable shape** — a random 12-character string that looks like a word is left alone. Add a `customRules` pattern if you need it.
- **Secrets split across lines** or embedded in images, archives, or binary files.

Other limits worth knowing:

- Restore works for **60 minutes after the last sanitize** (the TTL restarts on every run), and the vault remembers the last **20** sanitized texts. Older texts can still be restored with `--force`, which skips the fingerprint check.
- File permissions (`0o600` file, `0o700` directory) are applied on macOS and Linux. Windows has no equivalent, so the vault is protected by your user profile ACL only.
- `watch` polls every 500ms; a clipboard change made in that window is picked up on the next tick.

## Configuration

`paste-safe` reads `.paste-saferc.json` from the current folder, falling back to `~/.paste-saferc.json`.

```json
{
  "customRules": [
    { "name": "INTERNAL_TOKEN", "pattern": "int_[a-z0-9]{32}", "flags": "g" }
  ],
  "allowlist": ["dev-only-token", "https://localhost:3000/.*"],
  "vaultTtlMinutes": 60
}
```

- `customRules` — extra patterns, applied after the built-in rules and before PII.
- `allowlist` — exact strings or regexes that are never redacted.
- `vaultTtlMinutes` — vault lifetime in minutes (default `60`), counted from the last sanitize.

Invalid JSON or an invalid `customRules` regex prints a clear error and exits non-zero instead of silently doing the wrong thing. An `allowlist` entry that is not a valid regex is matched literally.

## Security & Trust

- **100% offline.** No network calls, no telemetry, no accounts. Detection is deterministic regex matching; nothing is sent anywhere.
- **The vault stores originals in plaintext.** `~/.paste-safe/last-map.json` holds the placeholder → original mapping in clear text so `restore` can work. It is created with `0o600` / `0o700` on macOS and Linux, and it deletes itself after the TTL. If that is not acceptable, use `--no-vault` and never write it.
- **Zero-disk mode.** `paste-safe --no-vault` never writes the mapping; redaction is one-way.
- **Preview-safe.** `--dry-run` and `--check` only ever print masked values (`sk_l...ABCD`), so your shell history stays clean.

## Headless / SSH / WSL

`clipboardy` needs a clipboard backend. If none is available, `paste-safe` tells you exactly what to do:

```bash
cat build.log | paste-safe --stdin          # pipe instead
sudo apt install xclip                      # X11
sudo apt install wl-clipboard               # Wayland
```

## Development

```bash
npm install
npm run typecheck
npm test        # builds, then runs unit + CLI integration tests
npm run build
```

Issues and pull requests are welcome — please read [SECURITY.md](SECURITY.md) before reporting a detection bypass.

## License

[MIT](LICENSE) © Purushottam Kumar
