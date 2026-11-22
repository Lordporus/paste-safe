import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const DEFAULT_TTL_MINUTES = 60;

/** How many sanitized-text fingerprints the vault remembers. */
export const MAX_HASHES = 20;

export interface VaultRecord {
  version: number;
  createdAt: number;
  expiresAt: number;
  /** SHA-256 of every sanitized text this vault produced (most recent last). */
  hashes: string[];
  map: Record<string, string>;
}

export function hashText(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export type VaultRead =
  | { status: 'ok'; record: VaultRecord; path: string }
  | { status: 'missing' }
  | { status: 'expired' }
  | { status: 'corrupt' };

export function defaultVaultDir(): string {
  return join(homedir(), '.paste-safe');
}

export function vaultPath(dir = defaultVaultDir()): string {
  return join(dir, 'last-map.json');
}

export function saveVault(
  map: Record<string, string>,
  ttlMinutes = DEFAULT_TTL_MINUTES,
  dir = defaultVaultDir(),
  text?: string,
): string {
  const file = vaultPath(dir);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  // chmod is best-effort: a no-op on Windows and on filesystems that refuse it.
  try {
    chmodSync(dir, 0o700);
  } catch {
    /* ignore */
  }

  const now = Date.now();
  // Merge with the live vault so placeholders from earlier runs stay restorable.
  const previous = readVault(dir);
  const mergedMap = { ...(previous.status === 'ok' ? previous.record.map : {}), ...map };
  const hashes = previous.status === 'ok' ? [...previous.record.hashes] : [];
  if (text !== undefined) hashes.push(hashText(text));

  const record: VaultRecord = {
    version: 2,
    createdAt: now,
    expiresAt: now + ttlMinutes * 60_000,
    hashes: hashes.slice(-MAX_HASHES),
    map: mergedMap,
  };
  writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
  try {
    chmodSync(file, 0o600);
  } catch {
    /* ignore */
  }
  return file;
}

export function readVault(dir = defaultVaultDir()): VaultRead {
  const file = vaultPath(dir);
  if (!existsSync(file)) return { status: 'missing' };

  let record: VaultRecord;
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as Partial<VaultRecord>;
    if (typeof parsed?.expiresAt !== 'number' || typeof parsed?.map !== 'object' || parsed.map === null) {
      rmSync(file, { force: true });
      return { status: 'corrupt' };
    }
    record = {
      version: parsed.version ?? 1,
      createdAt: parsed.createdAt ?? 0,
      expiresAt: parsed.expiresAt,
      hashes: Array.isArray(parsed.hashes) ? parsed.hashes.filter((h): h is string => typeof h === 'string') : [],
      map: parsed.map,
    };
  } catch {
    rmSync(file, { force: true });
    return { status: 'corrupt' };
  }

  if (Date.now() >= record.expiresAt) {
    rmSync(file, { force: true });
    return { status: 'expired' };
  }
  return { status: 'ok', record, path: file };
}

export function clearVault(dir = defaultVaultDir()): boolean {
  const file = vaultPath(dir);
  if (!existsSync(file)) return false;
  rmSync(file, { force: true });
  return true;
}

/** Replace placeholders back to originals. Longest keys first; no regex involved. */
export function restoreText(text: string, map: Record<string, string>): string {
  const keys = Object.keys(map).sort((a, b) => b.length - a.length);
  let out = text;
  for (const key of keys) {
    out = out.split(key).join(map[key] ?? '');
  }
  return out;
}
