/**
 * Overlap-safe secret & PII detection.
 * Pure, offline, deterministic: no network, no clock, no randomness.
 *
 * Rules run in priority order and claim character spans. Once a span is
 * claimed, lower-priority rules can never match inside it.
 */

export interface CustomRule {
  name: string;
  pattern: string;
  flags?: string;
}

export interface RedactOptions {
  pii?: boolean;
  customRules?: CustomRule[];
  allowlist?: string[];
  /** Placeholders already in the vault; numbering continues after them so runs never collide. */
  reserved?: string[];
}

export interface Finding {
  rule: string;
  placeholder: string;
  start: number;
  end: number;
  raw: string;
}

export interface RedactResult {
  text: string;
  findings: Finding[];
  counts: Record<string, number>;
  map: Record<string, string>;
}

interface Rule {
  name: string;
  re: RegExp;
  /** Strip trailing punctuation from the matched raw value. */
  trim?: boolean;
  /** Characters stripped by `trim`. Defaults to sentence punctuation. */
  trimChars?: RegExp;
  /** Secret portion of the match, used for dedupe + preview. Defaults to m[0]. */
  raw?: (m: RegExpExecArray) => string;
  /** Text preserved before the placeholder (e.g. "KEY=" or "Authorization: Bearer "). */
  prefix?: (m: RegExpExecArray) => string;
  /** Text preserved after the placeholder (e.g. a closing quote). */
  suffix?: (m: RegExpExecArray) => string;
  accept?: (raw: string) => boolean;
}

interface Hit {
  start: number;
  end: number;
  replacement: string;
  finding: Finding;
}

const BASE_RULES: Rule[] = [
  // 1. Private key blocks
  {
    name: 'PRIVATE_KEY',
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  },
  // 2. Database / broker URIs with credentials
  {
    name: 'DB_URI',
    re: /\b(?:postgresql|postgres|mongodb\+srv|mongodb|rediss|redis|mysql|amqp):\/\/[^\s"'`<>]+/g,
    trim: true,
    accept: (raw) => /^[a-z][a-z+]*:\/\/[^/\s@]+:[^/\s@]+@/i.test(raw),
  },
  // 3. Provider-specific tokens
  { name: 'AWS_KEY', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'GITHUB_TOKEN', re: /\b(?:gh[pous]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g },
  { name: 'STRIPE_KEY', re: /\b(?:sk|pk|rk)_live_[A-Za-z0-9]{10,}\b|\bsk_test_[A-Za-z0-9]{10,}\b/g },
  {
    name: 'API_KEY',
    re: /\bsk-ant-[A-Za-z0-9_-]{10,}|\bsk-proj-[A-Za-z0-9_-]{10,}|\bsk-[A-Za-z0-9_-]{20,}/g,
    trim: true,
    trimChars: /[-_]+$/,
  },
  { name: 'GOOGLE_KEY', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'SLACK_TOKEN', re: /\bxox[baprs]-[0-9A-Za-z-]+/g },
  { name: 'HF_TOKEN', re: /\bhf_[A-Za-z0-9]{20,}\b/g },
  { name: 'NPM_TOKEN', re: /\bnpm_[A-Za-z0-9]{20,}\b/g },
  // 4. JWTs
  { name: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  // 5. HTTP auth headers (prefix preserved)
  {
    name: 'AUTH_TOKEN',
    re: /\b((?:proxy-)?authorization[ \t]*:[ \t]*(?:bearer|basic)[ \t]+)([A-Za-z0-9._~+/=-]+)/gi,
    raw: (m) => m[2] ?? '',
    prefix: (m) => m[1] ?? '',
  },
  // 6. .env-style assignments (key + `=` preserved)
  {
    name: 'ENV_SECRET',
    re: /([A-Za-z0-9_.-]*(?:SECRET|TOKEN|PASSWD|PASSWORD|API_KEY|PRIVATE_KEY|ACCESS_KEY|AUTH)[A-Za-z0-9_.-]*[ \t]*=[ \t]*)(?:"([^"\n]*)"|'([^'\n]*)'|([^\s]+))/g,
    raw: (m) => envParts(m).raw,
    prefix: (m) => (m[1] ?? '') + envParts(m).quote,
    suffix: (m) => envParts(m).quote + envParts(m).sep,
  },
];

// 7. PII (lowest priority, opt-out with --no-pii)
const PII_RULES: Rule[] = [
  {
    name: 'EMAIL',
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    accept: (raw) => !/@(?:[A-Za-z0-9-]+\.)*example\.com$/i.test(raw),
  },
  {
    name: 'IP',
    re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    accept: isRealIp,
  },
];

function isRealIp(raw: string): boolean {
  const parts = raw.split('.');
  if (parts.length !== 4) return false;
  if (!parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)) return false;
  return raw !== '127.0.0.1' && raw !== '0.0.0.0';
}

/** Split an .env value into the secret, its quote, and any trailing shell separator. */
function envParts(m: RegExpExecArray): { raw: string; quote: string; sep: string } {
  const quote = m[2] !== undefined ? '"' : m[3] !== undefined ? "'" : '';
  let raw = m[2] ?? m[3] ?? m[4] ?? '';
  let sep = '';
  if (quote === '' && raw.length > 1) {
    const tail = /([;|&]+)$/.exec(raw);
    if (tail && tail[1].length < raw.length) {
      sep = tail[1];
      raw = raw.slice(0, -sep.length);
    }
  }
  return { raw, quote, sep };
}

const PLACEHOLDER_WORDS = /^(?:your[_-]?(?:api[_-]?)?key|changeme|change[_-]?me|xxx+|redacted|example|dummy|placeholder|todo|fixme)$/i;

/** Values that are already placeholders and should never be redacted. */
function isPlaceholderValue(raw: string): boolean {
  const s = raw.trim();
  if (s === '') return true;
  if (s.startsWith('<') && s.endsWith('>')) return true;
  if (PLACEHOLDER_WORDS.test(s)) return true;
  if (/^[x*._-]+$/i.test(s)) return true;
  return false;
}

function sanitizeRuleName(name: string): string {
  const cleaned = name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  return cleaned || 'CUSTOM';
}

function compileCustom(pattern: string, flags = ''): RegExp {
  const set = new Set(flags.replace(/[gy]/g, ''));
  set.add('g');
  return new RegExp(pattern, [...set].join(''));
}

function buildRules(opts: RedactOptions): Rule[] {
  const rules = [...BASE_RULES];
  for (const custom of opts.customRules ?? []) {
    rules.push({ name: sanitizeRuleName(custom.name), re: compileCustom(custom.pattern, custom.flags) });
  }
  if (opts.pii !== false) rules.push(...PII_RULES);
  return rules;
}

type AllowMatcher = (raw: string) => boolean;

function compileAllowlist(entries: string[]): AllowMatcher[] {
  return entries.map((entry) => {
    let re: RegExp | null = null;
    try {
      re = new RegExp(entry);
    } catch {
      re = null;
    }
    return (raw: string) => raw === entry || (re !== null && re.test(raw));
  });
}

function overlaps(claimed: Uint8Array, start: number, end: number): boolean {
  for (let i = start; i < end; i += 1) {
    if (claimed[i] === 1) return true;
  }
  return false;
}

export function redact(text: string, opts: RedactOptions = {}): RedactResult {
  const rules = buildRules(opts);
  const allow = compileAllowlist(opts.allowlist ?? []);
  const claimed = new Uint8Array(text.length);
  const hits: Hit[] = [];
  const counters = new Map<string, number>();
  const seen = new Map<string, string>();

  for (const placeholder of opts.reserved ?? []) {
    const match = /^<([A-Z0-9_]+)_(\d+)>$/.exec(placeholder);
    if (match) counters.set(match[1], Math.max(counters.get(match[1]) ?? 0, Number(match[2])));
  }

  for (const rule of rules) {
    const re = new RegExp(rule.re.source, rule.re.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex += 1;
        continue;
      }
      const start = m.index;
      let end = start + m[0].length;
      let raw = rule.raw ? rule.raw(m) : m[0];
      if (rule.trim) {
        const trimmed = raw.replace(rule.trimChars ?? /[.,;:)\]}]+$/, '');
        end -= raw.length - trimmed.length;
        raw = trimmed;
      }
      if (raw === '' || end <= start) continue;
      if (overlaps(claimed, start, end)) continue;
      if (rule.accept && !rule.accept(raw)) continue;
      if (isPlaceholderValue(raw)) continue;
      if (allow.some((match) => match(raw))) continue;

      let placeholder = seen.get(raw);
      if (!placeholder) {
        const n = (counters.get(rule.name) ?? 0) + 1;
        counters.set(rule.name, n);
        placeholder = `<${rule.name}_${n}>`;
        seen.set(raw, placeholder);
      }

      claimed.fill(1, start, end);
      const finding: Finding = { rule: rule.name, placeholder, start, end, raw };
      const replacement = (rule.prefix ? rule.prefix(m) : '') + placeholder + (rule.suffix ? rule.suffix(m) : '');
      hits.push({ start, end, replacement, finding });
    }
  }

  hits.sort((a, b) => a.start - b.start);

  let out = '';
  let cursor = 0;
  for (const hit of hits) {
    out += text.slice(cursor, hit.start) + hit.replacement;
    cursor = hit.end;
  }
  out += text.slice(cursor);

  const counts: Record<string, number> = {};
  const map: Record<string, string> = {};
  for (const hit of hits) {
    counts[hit.finding.rule] = (counts[hit.finding.rule] ?? 0) + 1;
    map[hit.finding.placeholder] = hit.finding.raw;
  }

  return { text: out, findings: hits.map((hit) => hit.finding), counts, map };
}

/** First 4 + "..." + last 4, or "***" for short values, so previews never leak. */
export function maskPreview(value: string): string {
  if (value.length < 12) return '***';
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}
