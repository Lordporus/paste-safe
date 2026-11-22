import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const CLI = join(process.cwd(), 'dist', 'cli.js');
const homes: string[] = [];

function home(): string {
  const dir = mkdtempSync(join(tmpdir(), 'paste-safe-cli-'));
  homes.push(dir);
  return dir;
}

function run(args: string[], input: string, dir = home()) {
  return spawnSync(process.execPath, [CLI, ...args], {
    input,
    encoding: 'utf8',
    env: { ...process.env, USERPROFILE: dir, HOME: dir },
  });
}

afterEach(() => {
  for (const dir of homes.splice(0)) rmSync(dir, { recursive: true, force: true });
});

const SECRET = 'TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwx\n';

describe('cli: sanitize', () => {
  it('keeps the sanitized text off stdout in a dry run', () => {
    const res = run(['--dry-run', '--stdin'], 'DATABASE_URL=postgres://admin:s3cr3t@10.0.0.5:5432/prod\n');
    expect(res.status).toBe(0);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain('<DB_URI_1>');
  });

  it('--check exits 1 on a secret, 0 on clean text, and prints nothing to stdout', () => {
    const dirty = run(['--check', '--stdin'], SECRET);
    expect(dirty.status).toBe(1);
    expect(dirty.stdout).toBe('');

    const clean = run(['--check', '--stdin'], 'nothing to see here\n');
    expect(clean.status).toBe(0);
    expect(clean.stdout).toBe('');
  });

  it('--check leaves no vault behind', () => {
    const dir = home();
    run(['--check', '--stdin'], SECRET, dir);
    expect(existsSync(join(dir, '.paste-safe'))).toBe(false);
  });

  it('--json writes parseable JSON to stdout with the output field', () => {
    const res = run(['--json', '--stdin'], SECRET);
    expect(res.status).toBe(0);
    expect(res.stdout).not.toMatch(/\u001b\[/);
    const body = JSON.parse(res.stdout) as { total: number; output: string; findings: { preview: string }[] };
    expect(body.total).toBe(1);
    expect(body.output).toBe('TOKEN=<GITHUB_TOKEN_1>\n');
    expect(body.findings[0]?.preview).not.toContain('ghp_1234567890abcdefghijklmnopqrstuvwx');
  });

  it('emits piped output byte-exactly', () => {
    const res = run(['--stdin'], 'TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwx');
    expect(res.stdout).toBe('TOKEN=<GITHUB_TOKEN_1>');
  });

  it('--no-vault and --dry-run leave no vault behind', () => {
    const noVault = home();
    run(['--no-vault', '--stdin'], SECRET, noVault);
    expect(existsSync(join(noVault, '.paste-safe'))).toBe(false);

    const dry = home();
    run(['--dry-run', '--stdin'], SECRET, dry);
    expect(existsSync(join(dry, '.paste-safe'))).toBe(false);
  });
});

describe('cli: restore', () => {
  it('round-trips the original text exactly', () => {
    const dir = home();
    const original = 'contact jane@acme.io\nPASSWORD="a\\"b"\n';
    const sanitized = run(['--stdin'], original, dir);
    expect(sanitized.status).toBe(0);
    expect(sanitized.stdout).not.toContain('jane@acme.io');

    const restored = run(['restore', '--stdin'], sanitized.stdout, dir);
    expect(restored.status).toBe(0);
    expect(restored.stdout).toBe(original);
  });

  it('says nothing to restore instead of failing on text without placeholders', () => {
    const dir = home();
    run(['--stdin'], SECRET, dir);
    const res = run(['restore', '--stdin'], 'no placeholders here\n', dir);
    expect(res.status).toBe(0);
    expect(res.stderr).toContain('nothing to restore');
  });
});
