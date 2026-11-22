import { existsSync, mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { clearVault, hashText, readVault, restoreText, saveVault, vaultPath } from '../src/vault.js';
import { redact } from '../src/detector.js';

const dirs: string[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'paste-safe-'));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of dirs.splice(0)) clearVault(dir);
});

describe('vault', () => {
  it('round-trips redact -> save -> load -> restore exactly', () => {
    const original = [
      'DATABASE_URL=postgres://admin:s3cr3t@10.0.0.5:5432/prod',
      'STRIPE=sk_live_FAKE1234567890ABCD',
      'mail jane.doe@acme.io',
      'AUTH="quoted-secret-value"',
    ].join('\n');

    const res = redact(original);
    const dir = tempDir();
    saveVault(res.map, 60, dir, res.text);

    const read = readVault(dir);
    expect(read.status).toBe('ok');
    if (read.status !== 'ok') return;
    expect(restoreText(res.text, read.record.map)).toBe(original);
  });

  it('expires and deletes the vault after its TTL', () => {
    const dir = tempDir();
    saveVault({ '<IP_1>': '10.0.0.5' }, 0, dir);
    expect(readVault(dir).status).toBe('expired');
    expect(readVault(dir).status).toBe('missing');
  });

  it('reports a missing vault', () => {
    expect(readVault(tempDir()).status).toBe('missing');
  });

  it('clears the vault file', () => {
    const dir = tempDir();
    saveVault({ '<IP_1>': '10.0.0.5' }, 60, dir);
    expect(clearVault(dir)).toBe(true);
    expect(clearVault(dir)).toBe(false);
    expect(readVault(dir).status).toBe('missing');
  });

  it('removes the vault directory once it is empty', () => {
    const dir = tempDir();
    saveVault({ '<IP_1>': '10.0.0.5' }, 60, dir);
    clearVault(dir);
    expect(existsSync(dir)).toBe(false);
  });

  it('writes a vault file with the expected shape', () => {
    const dir = tempDir();
    saveVault({ '<IP_1>': '10.0.0.5' }, 60, dir);
    const record = JSON.parse(readFileSync(vaultPath(dir), 'utf8')) as { map: Record<string, string>; expiresAt: number };
    expect(record.map).toEqual({ '<IP_1>': '10.0.0.5' });
    expect(record.expiresAt).toBeGreaterThan(Date.now());
  });

  it('fingerprints every sanitized text it produced', () => {
    const dir = tempDir();
    saveVault({ '<IP_1>': '10.0.0.5' }, 60, dir, 'host <IP_1>');
    saveVault({ '<EMAIL_1>': 'a@b.io' }, 60, dir, 'mail <EMAIL_1>');
    const read = readVault(dir);
    expect(read.status).toBe('ok');
    if (read.status !== 'ok') return;
    expect(read.record.hashes).toEqual([hashText('host <IP_1>'), hashText('mail <EMAIL_1>')]);
  });

  it('merges maps across runs so earlier placeholders stay restorable', () => {
    const dir = tempDir();
    saveVault({ '<EMAIL_1>': 'jane@acme.io' }, 60, dir, 'contact <EMAIL_1>');
    saveVault({ '<EMAIL_2>': 'bob@acme.io' }, 60, dir, 'contact <EMAIL_2>');
    const read = readVault(dir);
    expect(read.status).toBe('ok');
    if (read.status !== 'ok') return;
    expect(read.record.map).toEqual({ '<EMAIL_1>': 'jane@acme.io', '<EMAIL_2>': 'bob@acme.io' });
  });

  it.skipIf(process.platform === 'win32')('restricts file permissions to 0600', () => {
    const dir = tempDir();
    saveVault({ '<IP_1>': '10.0.0.5' }, 60, dir);
    expect(statSync(vaultPath(dir)).mode & 0o777).toBe(0o600);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
  });
});

describe('restoreText', () => {
  it('replaces the longest placeholder first', () => {
    const map = { '<IP_1>': 'one', '<IP_10>': 'ten' };
    expect(restoreText('a <IP_10> b <IP_1>', map)).toBe('a ten b one');
  });

  it('leaves unknown placeholders untouched', () => {
    expect(restoreText('keep <EMAIL_9>', { '<IP_1>': 'x' })).toBe('keep <EMAIL_9>');
  });
});
