import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../src/config.js';

function configDir(contents: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'paste-safe-cfg-'));
  writeFileSync(join(dir, '.paste-saferc.json'), contents);
  return dir;
}

describe('config', () => {
  it('falls back to defaults with no config file', () => {
    const cfg = loadConfig(mkdtempSync(join(tmpdir(), 'paste-safe-cfg-')));
    expect(cfg).toMatchObject({ customRules: [], allowlist: [], vaultTtlMinutes: 60, path: null });
  });

  it('loads custom rules, allowlist and ttl', () => {
    const dir = configDir(
      JSON.stringify({ customRules: [{ name: 'x', pattern: 'x_[0-9]+' }], allowlist: ['ok'], vaultTtlMinutes: 5 }),
    );
    expect(loadConfig(dir)).toMatchObject({
      customRules: [{ name: 'x', pattern: 'x_[0-9]+', flags: undefined }],
      allowlist: ['ok'],
      vaultTtlMinutes: 5,
    });
  });

  it('rejects invalid JSON', () => {
    expect(() => loadConfig(configDir('{ nope'))).toThrow(ConfigError);
  });

  it('rejects an invalid custom-rule regex', () => {
    expect(() => loadConfig(configDir(JSON.stringify({ customRules: [{ name: 'x', pattern: '([' }] })))).toThrow(
      ConfigError,
    );
  });

  it('accepts an allowlist entry that is not a valid regex', () => {
    expect(loadConfig(configDir(JSON.stringify({ allowlist: ['a(b'] }))).allowlist).toEqual(['a(b']);
  });

  it('rejects a non-positive ttl', () => {
    expect(() => loadConfig(configDir(JSON.stringify({ vaultTtlMinutes: 0 })))).toThrow(ConfigError);
  });
});
