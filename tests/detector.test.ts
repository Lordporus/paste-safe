import { describe, expect, it } from 'vitest';
import { maskPreview, redact } from '../src/detector.js';

const AWS = 'AKIAIOSFODNN7EXAMPLE';

describe('detector: secrets', () => {
  it('redacts multi-line private key blocks', () => {
    const key = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc123\n-----END RSA PRIVATE KEY-----';
    expect(redact(`before\n${key}\nafter`).text).toBe('before\n<PRIVATE_KEY_1>\nafter');
  });

  it('stays fast on many unterminated private-key headers', () => {
    const text = `${'-----BEGIN RSA PRIVATE KEY-----\n'.repeat(500)}${'x'.repeat(1_000_000)}`;
    const started = Date.now();
    expect(redact(text).findings).toHaveLength(0);
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it('redacts an escaped-quote .env value without corrupting it', () => {
    const res = redact('PASSWORD="a\\"b"');
    expect(res.text).toBe('PASSWORD="<ENV_SECRET_1>"');
    expect(res.map['<ENV_SECRET_1>']).toBe('a\\"b');
  });

  it('redacts every credentialed database / broker URI scheme', () => {
    for (const scheme of ['postgres', 'postgresql', 'mongodb', 'mongodb+srv', 'redis', 'rediss', 'mysql', 'amqp']) {
      const uri = `${scheme}://user:pass@db.internal:5432/app`;
      expect(redact(uri).text).toBe('<DB_URI_1>');
    }
  });

  it('leaves credential-less URIs alone', () => {
    const text = 'postgres://db.internal:5432/app';
    expect(redact(text).text).toBe(text);
  });

  it('redacts AWS access keys', () => {
    expect(redact(AWS).text).toBe('<AWS_KEY_1>');
    expect(redact('ASIAIOSFODNN7EXAMPLE').text).toBe('<AWS_KEY_1>');
  });

  it('redacts GitHub tokens', () => {
    expect(redact('ghp_1234567890abcdefghijklmnopqrstuvwx').text).toBe('<GITHUB_TOKEN_1>');
    expect(redact('github_pat_11ABCDEFG0123456789_abcdefghijklmnop').text).toBe('<GITHUB_TOKEN_1>');
  });

  it('redacts Stripe keys', () => {
    expect(redact('sk_live_FAKE1234567890ABCD').text).toBe('<STRIPE_KEY_1>');
    expect(redact('pk_live_51AbcDefGhIjKlMnOpQrStUvWx').text).toBe('<STRIPE_KEY_1>');
    expect(redact('sk_test_51AbcDefGhIjKlMnOpQrStUvWx').text).toBe('<STRIPE_KEY_1>');
  });

  it('redacts OpenAI / Anthropic / DeepSeek / generic sk- keys', () => {
    expect(redact('sk-ant-api03-abcdefghijklmnopqrstuvwx').text).toBe('<API_KEY_1>');
    expect(redact('sk-proj-AbCdEf1234567890GhIjKl').text).toBe('<API_KEY_1>');
    expect(redact('sk-abcdefghijklmnopqrstuvwx').text).toBe('<API_KEY_1>');
  });

  it('redacts Google, Slack, Hugging Face and npm tokens', () => {
    expect(redact('AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI').text).toBe('<GOOGLE_KEY_1>');
    expect(redact('xoxb-123456789012-abcdefghijkl').text).toBe('<SLACK_TOKEN_1>');
    expect(redact('hf_abcdefghijklmnopqrstuvwxyz0123456789').text).toBe('<HF_TOKEN_1>');
    expect(redact('npm_abcdefghijklmnopqrstuvwxyz0123456789').text).toBe('<NPM_TOKEN_1>');
  });

  it('redacts JWTs', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    expect(redact(jwt).text).toBe('<JWT_1>');
  });

  it('redacts auth header tokens but keeps the prefix', () => {
    expect(redact('Authorization: Bearer abc123.def-456_ghi').text).toBe('Authorization: Bearer <AUTH_TOKEN_1>');
    expect(redact('authorization: Basic dXNlcjpwYXNz').text).toBe('authorization: Basic <AUTH_TOKEN_1>');
  });

  it('redacts .env-style assignments but keeps the key', () => {
    expect(redact('API_KEY=supersecretvalue123').text).toBe('API_KEY=<ENV_SECRET_1>');
    expect(redact('export DB_PASSWORD="hunter2hunter2"').text).toBe('export DB_PASSWORD="<ENV_SECRET_1>"');
    expect(redact('MY_ACCESS_KEY=abcd1234efgh').text).toBe('MY_ACCESS_KEY=<ENV_SECRET_1>');
  });

  it('keeps # inside an unquoted value and treats " #" as a comment', () => {
    expect(redact('PASSWORD=abc#def').text).toBe('PASSWORD=<ENV_SECRET_1>');
    expect(redact('PASSWORD=abc # note').text).toBe('PASSWORD=<ENV_SECRET_1> # note');
  });

  it('keeps a trailing shell separator outside the placeholder', () => {
    expect(redact('export TOKEN=abc123; export OTHER=1').text).toBe('export TOKEN=<ENV_SECRET_1>; export OTHER=1');
    expect(redact('TOKEN=abc123&& curl x').text).toBe('TOKEN=<ENV_SECRET_1>&& curl x');
  });

  it('fully redacts hyphenated sk- keys', () => {
    expect(redact('API_KEY=sk-abcdefghijklmnopqrstuvwx-SUFFIX').text).toBe('API_KEY=<API_KEY_1>');
    expect(redact('sk-abcdefghijklmnopqrstuvwx-').text).toBe('<API_KEY_1>-');
  });
});

describe('detector: PII', () => {
  it('redacts emails and IPv4 addresses by default', () => {
    const out = redact('contact jane.doe@acme.io from 192.168.1.42').text;
    expect(out).toBe('contact <EMAIL_1> from <IP_1>');
  });

  it('keeps PII when pii is disabled', () => {
    const text = 'contact jane.doe@acme.io from 192.168.1.42';
    expect(redact(text, { pii: false }).text).toBe(text);
  });
});

describe('detector: overlap safety', () => {
  it('never re-matches inside a claimed DB URI', () => {
    const out = redact('DATABASE_URL=postgres://admin:s3cr3t@10.0.0.5:5432/prod');
    expect(out.text).toBe('DATABASE_URL=<DB_URI_1>');
    expect(out.findings.map((f) => f.rule)).toEqual(['DB_URI']);
  });

  it('lets a provider token win over an .env assignment', () => {
    const out = redact('TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwx');
    expect(out.text).toBe('TOKEN=<GITHUB_TOKEN_1>');
    expect(out.findings).toHaveLength(1);
  });

  it('reuses one placeholder for identical values', () => {
    const out = redact(`${AWS} and ${AWS}`);
    expect(out.text).toBe('<AWS_KEY_1> and <AWS_KEY_1>');
    expect(out.counts.AWS_KEY).toBe(2);
    expect(Object.keys(out.map)).toEqual(['<AWS_KEY_1>']);
  });
});

describe('detector: false positives', () => {
  it.each([
    '127.0.0.1',
    '0.0.0.0',
    'localhost:3000',
    'v1.2.3',
    'release v2.10.4 shipped',
    'user@example.com',
    'API_KEY=YOUR_API_KEY',
    'PASSWORD=changeme',
    'note <REDACTED> here',
    'xxx',
  ])('leaves %s untouched', (text) => {
    expect(redact(text).text).toBe(text);
  });
});

describe('detector: customization', () => {
  it('applies custom rules', () => {
    const out = redact('leaked int_abcdefghijklmnopqrstuvwxyz012345', {
      customRules: [{ name: 'internal', pattern: 'int_[a-z0-9]{32}' }],
    });
    expect(out.text).toBe('leaked <INTERNAL_1>');
  });

  it('honors an exact allowlist entry', () => {
    expect(redact(AWS, { allowlist: [AWS] }).text).toBe(AWS);
  });

  it('honors a regex allowlist entry', () => {
    expect(redact(AWS, { allowlist: ['AKIA.*'] }).text).toBe(AWS);
  });

  it('falls back to exact matching for an allowlist entry that is not a valid regex', () => {
    const text = 'literal a(b value';
    expect(redact(text, { allowlist: ['a(b'] }).text).toBe(text);
  });

  it('continues numbering after placeholders already in the vault', () => {
    expect(redact('jane@acme.io', { reserved: ['<EMAIL_1>'] }).text).toBe('<EMAIL_2>');
    expect(redact('jane@acme.io', { reserved: ['<EMAIL_1>', '<EMAIL_7>'] }).text).toBe('<EMAIL_8>');
    expect(redact('jane@acme.io', { reserved: ['<AWS_KEY_3>'] }).text).toBe('<EMAIL_1>');
  });
});

describe('maskPreview', () => {
  it('keeps only the first and last four characters', () => {
    expect(maskPreview('sk_live_FAKE1234567890ABCD')).toBe('sk_l...ABCD');
  });

  it('fully masks short values', () => {
    expect(maskPreview('hunter2')).toBe('***');
  });
});
