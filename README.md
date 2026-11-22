# paste-safe

**Redact secrets and PII from your clipboard before you paste logs into an AI chat or a GitHub issue.**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Lordporus/paste-safe/actions/workflows/ci.yml/badge.svg)](https://github.com/Lordporus/paste-safe/actions/workflows/ci.yml)
![Zero Network](https://img.shields.io/badge/network-zero-brightgreen)

<!-- demo.gif: record the 3-second quickstart here (asciinema/vhs) and uncomment the image below. -->
<!-- ![demo](./demo.gif) -->

## Quickstart

```bash
npx paste-safe
```

Copy anything risky. Run it. Paste safely.

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

## Security & Trust

- **100% offline.** No network calls, no telemetry, no accounts. Detection is deterministic regex matching, nothing is sent anywhere.
- **Auto-expiring vault.** The placeholder → original map lives at `~/.paste-safe/last-map.json` with `0o600` file / `0o700` directory permissions and a **60 minute** TTL. On expiry it deletes itself.
- **Zero-disk mode.** `paste-safe --no-vault` never writes the mapping; redaction is one-way.
- **Preview-safe.** `--dry-run` only ever prints masked values (`sk_l...UvWx`), so your shell history stays clean.

## Commands

| Command | What it does |
| --- | --- |
| `paste-safe` | Sanitizes the clipboard (or piped stdin), copies the result back, saves the vault. |
| `paste-safe restore` | Restores placeholders using the local vault. |
| `paste-safe watch` | Polls the clipboard every 500ms and sanitizes secrets in place. |
| `paste-safe clear` | Deletes the local vault immediately. |
| `paste-safe init` | Writes a starter `.paste-saferc.json`. |

## Flags

| Flag | Effect |
| --- | --- |
| `--dry-run` | Preview detections with masked values; writes nothing, to clipboard or disk. |
| `--no-pii` | Redact secrets only; keep emails and IPs. |
| `--no-vault` | One-way redaction; never touch disk. |
| `--check` | Exit `1` when anything is detected, `0` when clean. |
| `--json` | Structured JSON summary (counts + masked previews + the sanitized `output`); stdout stays pure JSON. |
| `--stdin` | Force reading stdin and writing stdout. |

Piping is auto-detected, so `cat error.log | paste-safe` just works. In that mode the sanitized text goes to stdout and the summary to stderr, keeping pipelines clean.

### Pre-commit example

```bash
git diff --cached | paste-safe --check --no-vault --stdin
```

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
- `vaultTtlMinutes` — vault lifetime in minutes (default `60`).

Invalid JSON or an invalid `customRules` regex prints a clear error and exits non-zero instead of silently doing the wrong thing. An `allowlist` entry that is not a valid regex is matched literally.

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
npm test
npm run build
```

## License

[MIT](LICENSE)
