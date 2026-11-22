import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Command } from 'commander';
import clipboardy from 'clipboardy';
import pc from 'picocolors';
import { maskPreview, redact, type RedactResult } from './detector.js';
import { ConfigError, loadConfig } from './config.js';
import { clearVault, hashText, readVault, restoreText, saveVault, vaultPath } from './vault.js';

interface GlobalOptions {
  dryRun?: boolean;
  pii?: boolean;
  vault?: boolean;
  check?: boolean;
  json?: boolean;
  stdin?: boolean;
  force?: boolean;
}

type Source = 'stdin' | 'clipboard';

class ClipboardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ClipboardError';
  }
}

const CLIPBOARD_HINT =
  'clipboard unavailable — pipe input instead (cat file.log | paste-safe --stdin) or install xclip (X11) / wl-clipboard (Wayland).';

function clipboardError(err: unknown): ClipboardError {
  const detail = err instanceof Error ? err.message : String(err);
  return new ClipboardError(detail ? `${CLIPBOARD_HINT} [${detail}]` : CLIPBOARD_HINT);
}

function readVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8')) as {
      version?: string;
    };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string));
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function readClipboard(): Promise<string> {
  try {
    return await clipboardy.read();
  } catch (err) {
    throw clipboardError(err);
  }
}

async function writeClipboard(text: string): Promise<void> {
  try {
    await clipboardy.write(text);
  } catch (err) {
    throw clipboardError(err);
  }
}

function writeStdout(text: string): void {
  process.stdout.write(text.endsWith('\n') ? text : `${text}\n`);
}

interface SummaryContext {
  dryRun: boolean;
  source: Source;
  destination: Source;
  vault: { saved: boolean; ttlMinutes: number };
}

function renderHuman(res: RedactResult, ctx: SummaryContext): string {
  if (res.findings.length === 0) return `${pc.dim('paste-safe: no secrets or PII found')}\n`;

  const total = res.findings.length;
  const action = ctx.dryRun
    ? `${pc.bold(String(total))} ${total === 1 ? 'match' : 'matches'} detected`
    : `${pc.bold(String(total))} ${total === 1 ? 'match' : 'matches'} redacted → ${ctx.destination === 'stdin' ? 'stdout' : 'clipboard'}`;
  const lines: string[] = [`${pc.green('✔')} ${action}`];
  const width = Math.max(...res.findings.map((finding) => maskPreview(finding.raw).length));
  const sep = ctx.dryRun ? pc.dim(' -> ') : '  ';
  for (const finding of res.findings) {
    lines.push(`  ${pc.dim(maskPreview(finding.raw).padEnd(width))}${sep}${pc.cyan(finding.placeholder)}`);
  }

  if (ctx.dryRun) {
    lines.push(`${pc.yellow('dry run')} — nothing was written`);
  } else if (ctx.vault.saved) {
    lines.push(`${pc.dim('saved')} ${pc.dim(vaultPath())} ${pc.dim(`(${ctx.vault.ttlMinutes}m)`)} · undo with ${pc.bold('paste-safe restore')}`);
  } else {
    lines.push(pc.dim('one-way redaction (--no-vault) — this cannot be undone'));
  }
  return `${lines.join('\n')}\n`;
}

function renderJson(res: RedactResult, ctx: SummaryContext): string {
  return `${JSON.stringify(
    {
      dryRun: ctx.dryRun,
      source: ctx.source,
      destination: ctx.destination,
      total: res.findings.length,
      counts: res.counts,
      findings: res.findings.map((finding) => ({
        rule: finding.rule,
        placeholder: finding.placeholder,
        preview: maskPreview(finding.raw),
      })),
      output: ctx.dryRun ? null : res.text,
      vault: ctx.vault,
    },
    null,
    2,
  )}\n`;
}

async function sanitizeCommand(o: GlobalOptions): Promise<void> {
  const config = loadConfig();
  const useStdin = Boolean(o.stdin) || !process.stdin.isTTY;
  const dryRun = Boolean(o.dryRun);
  const vaultOff = o.vault === false;

  const text = useStdin ? await readStdin() : await readClipboard();
  if (text.trim() === '') {
    process.stderr.write(pc.dim('paste-safe: nothing to sanitize\n'));
    return;
  }

  const existing = !dryRun && !vaultOff ? readVault() : { status: 'missing' as const };
  const reserved = existing.status === 'ok' ? Object.keys(existing.record.map) : [];

  const res = redact(text, {
    pii: o.pii !== false,
    customRules: config.customRules,
    allowlist: config.allowlist,
    reserved,
  });

  const json = Boolean(o.json);
  let saved = false;
  if (!dryRun) {
    // Save the vault first: if it fails, the clipboard stays untouched and restorable.
    if (!vaultOff && res.findings.length > 0) {
      saveVault(res.map, config.vaultTtlMinutes, undefined, res.text);
      saved = true;
    }
    if (!useStdin) await writeClipboard(res.text);
    else if (!json) writeStdout(res.text);
  }

  const ctx: SummaryContext = {
    dryRun,
    source: useStdin ? 'stdin' : 'clipboard',
    destination: useStdin ? 'stdin' : 'clipboard',
    vault: { saved, ttlMinutes: config.vaultTtlMinutes },
  };
  // --json owns stdout; without it, piped stdout stays pure text.
  if (json) process.stdout.write(renderJson(res, ctx));
  else (useStdin ? process.stderr : process.stdout).write(renderHuman(res, ctx));

  if (o.check && res.findings.length > 0) process.exitCode = 1;
}

async function restoreCommand(o: GlobalOptions): Promise<void> {
  const useStdin = Boolean(o.stdin) || !process.stdin.isTTY;
  const text = useStdin ? await readStdin() : await readClipboard();
  const read = readVault();
  const log = useStdin ? process.stderr : process.stdout;

  if (read.status !== 'ok') {
    const reason =
      read.status === 'missing'
        ? 'no vault found — nothing to restore'
        : read.status === 'expired'
          ? 'vault expired and was deleted — nothing to restore'
          : 'vault was corrupt and has been deleted';
    log.write(`${pc.yellow('paste-safe:')} ${reason}\n`);
    process.exitCode = 1;
    return;
  }

  const hashes = read.record.hashes;
  if (hashes.length > 0 && !hashes.includes(hashText(text)) && !o.force) {
    log.write(
      `${pc.yellow('paste-safe:')} this text was not produced by the current vault — it looks like it was sanitized in an earlier run.\n`,
    );
    log.write(pc.dim('  re-run paste-safe on the original text, or pass --force to restore anyway.\n'));
    process.exitCode = 1;
    return;
  }

  const out = restoreText(text, read.record.map);
  if (useStdin) writeStdout(out);
  else await writeClipboard(out);
  log.write(`${pc.green('✔')} restored → ${useStdin ? 'stdout' : 'clipboard'}\n`);
}

async function watchCommand(o: GlobalOptions): Promise<void> {
  const config = loadConfig();
  const vaultOff = o.vault === false;
  // Prime with what is already on the clipboard so starting watch does not rewrite it.
  let last = '';
  try {
    last = await readClipboard();
  } catch {
    /* the first tick reports the real error */
  }
  let busy = false;

  const tick = async (): Promise<void> => {
    if (busy) return;
    busy = true;
    try {
      const text = await readClipboard();
      if (!text || text === last) return;
      const res = redact(text, {
        pii: o.pii !== false,
        customRules: config.customRules,
        allowlist: config.allowlist,
      });
      if (res.findings.length === 0) {
        last = text;
        return;
      }
      await writeClipboard(res.text);
      last = res.text;
      if (!vaultOff) saveVault(res.map, config.vaultTtlMinutes);
      const stamp = new Date().toLocaleTimeString([], { hour12: false });
      const placeholders = [...new Set(res.findings.map((finding) => finding.placeholder))].join(' ');
      process.stdout.write(`${pc.dim(stamp)} ${pc.green('✔')} ${res.findings.length} redacted ${pc.cyan(placeholders)}\n`);
    } catch (err) {
      clearInterval(timer);
      const failure = err instanceof ClipboardError ? err : clipboardError(err);
      process.stderr.write(pc.red(`paste-safe: ${failure.message}\n`));
      process.exitCode = 1;
    } finally {
      busy = false;
    }
  };

  const timer = setInterval(() => void tick(), 500);

  process.on('SIGINT', () => {
    clearInterval(timer);
    process.stdout.write(`\n${pc.dim('paste-safe: watch stopped')}\n`);
    process.exit(0);
  });

  process.stdout.write(`${pc.dim('paste-safe: watching clipboard (500ms) — Ctrl+C to stop')}\n`);
}

function clearCommand(): void {
  process.stdout.write(clearVault() ? `${pc.green('✔')} vault cleared\n` : `${pc.dim('paste-safe: no vault to clear')}\n`);
}

const STARTER_CONFIG = {
  _help:
    'paste-safe config. customRules add your own patterns, allowlist keeps known-safe values out of redaction, vaultTtlMinutes controls how long `paste-safe restore` can undo a redaction.',
  customRules: [{ name: 'INTERNAL_TOKEN', pattern: 'int_[a-z0-9]{32}', flags: 'g' }],
  allowlist: ['dev-only-token', 'https://localhost:3000/.*'],
  vaultTtlMinutes: 60,
};

function initCommand(): void {
  const file = join(process.cwd(), '.paste-saferc.json');
  if (existsSync(file)) {
    process.stderr.write(`${pc.yellow('paste-safe:')} ${file} already exists\n`);
    process.exitCode = 1;
    return;
  }
  writeFileSync(file, `${JSON.stringify(STARTER_CONFIG, null, 2)}\n`);
  process.stdout.write(`${pc.green('✔')} created ${file}\n`);
}

async function run(fn: (o: GlobalOptions) => void | Promise<void>, cmd: Command): Promise<void> {
  try {
    await fn(cmd.optsWithGlobals<GlobalOptions>());
  } catch (err) {
    if (err instanceof ConfigError || err instanceof ClipboardError) {
      process.stderr.write(pc.red(`paste-safe: ${err.message}\n`));
    } else {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(pc.red(`paste-safe: unexpected error — ${message}\n`));
    }
    process.exit(1);
  }
}

const program = new Command();

program
  .name('paste-safe')
  .description('Redact secrets and PII from the clipboard (or stdin) before pasting into AI chats or GitHub issues.')
  .version(readVersion())
  .option('--dry-run', 'preview detections with masked values; never touch the clipboard or disk')
  .option('--no-pii', 'redact secrets only; keep emails and IPs')
  .option('--no-vault', 'one-way redaction; never write the vault')
  .option('--check', 'exit 1 when anything is detected')
  .option('--json', 'print a JSON summary')
  .option('--stdin', 'force reading stdin and writing stdout');

program
  .command('restore')
  .description('restore placeholders using the local vault')
  .option('--force', 'restore even if the text was not produced by the current vault')
  .action((_opts: unknown, cmd: Command) => run(restoreCommand, cmd));

program
  .command('watch')
  .description('poll the clipboard and sanitize secrets in place')
  .action((_opts: unknown, cmd: Command) => run(watchCommand, cmd));

program.command('clear').description('delete the local vault').action(() => run(clearCommand, program));

program
  .command('init')
  .description('create a starter .paste-saferc.json in the current folder')
  .action(() => run(initCommand, program));

program.action((_opts: unknown, cmd: Command) => run(sanitizeCommand, cmd));

await program.parseAsync();
