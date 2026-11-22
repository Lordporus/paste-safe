import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export interface CustomRule {
  name: string;
  pattern: string;
  flags?: string;
}

export interface PasteSafeConfig {
  customRules: CustomRule[];
  allowlist: string[];
  vaultTtlMinutes: number;
  path: string | null;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

export const DEFAULT_TTL_MINUTES = 60;

export function configCandidates(cwd = process.cwd()): string[] {
  return [join(cwd, '.paste-saferc.json'), join(homedir(), '.paste-saferc.json')];
}

export function loadConfig(cwd = process.cwd()): PasteSafeConfig {
  const file = configCandidates(cwd).find((candidate) => existsSync(candidate));
  if (!file) {
    return { customRules: [], allowlist: [], vaultTtlMinutes: DEFAULT_TTL_MINUTES, path: null };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    throw new ConfigError(`invalid JSON in ${file}: ${(err as Error).message}`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new ConfigError(`${file} must contain a JSON object`);
  }

  const obj = parsed as Record<string, unknown>;
  const customRules: CustomRule[] = [];
  const allowlist: string[] = [];
  let vaultTtlMinutes = DEFAULT_TTL_MINUTES;

  if (obj.customRules !== undefined) {
    if (!Array.isArray(obj.customRules)) throw new ConfigError(`${file}: "customRules" must be an array`);
    obj.customRules.forEach((entry, i) => {
      if (typeof entry !== 'object' || entry === null) {
        throw new ConfigError(`${file}: customRules[${i}] must be an object`);
      }
      const rule = entry as Record<string, unknown>;
      if (typeof rule.name !== 'string' || rule.name.trim() === '') {
        throw new ConfigError(`${file}: customRules[${i}].name must be a non-empty string`);
      }
      if (typeof rule.pattern !== 'string' || rule.pattern === '') {
        throw new ConfigError(`${file}: customRules[${i}].pattern must be a non-empty string`);
      }
      if (rule.flags !== undefined && typeof rule.flags !== 'string') {
        throw new ConfigError(`${file}: customRules[${i}].flags must be a string`);
      }
      try {
        new RegExp(rule.pattern, (rule.flags ?? '').replace(/[gy]/g, ''));
      } catch (err) {
        throw new ConfigError(`${file}: customRules[${i}] has an invalid regex: ${(err as Error).message}`);
      }
      customRules.push({ name: rule.name.trim(), pattern: rule.pattern, flags: rule.flags as string | undefined });
    });
  }

  if (obj.allowlist !== undefined) {
    if (!Array.isArray(obj.allowlist)) throw new ConfigError(`${file}: "allowlist" must be an array`);
    obj.allowlist.forEach((entry, i) => {
      if (typeof entry !== 'string') throw new ConfigError(`${file}: allowlist[${i}] must be a string`);
      // Not a regex? Still fine: it is matched literally.
      allowlist.push(entry);
    });
  }

  if (obj.vaultTtlMinutes !== undefined) {
    const ttl = obj.vaultTtlMinutes;
    if (typeof ttl !== 'number' || !Number.isFinite(ttl) || ttl <= 0) {
      throw new ConfigError(`${file}: "vaultTtlMinutes" must be a positive number`);
    }
    vaultTtlMinutes = ttl;
  }

  return { customRules, allowlist, vaultTtlMinutes, path: file };
}
