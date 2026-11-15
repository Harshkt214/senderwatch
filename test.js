import test from 'node:test';
import assert from 'node:assert/strict';
import { checkDomain, analyzeSpf, analyzeDmarc, normalizeDomain } from './checks.js';

const zone = {
  'good.com TXT': [{ type: 16, data: '"v=spf1 include:_spf.google.com ~all"' }],
  '_dmarc.good.com TXT': [{ type: 16, data: '"v=DMARC1; p=quarantine; rua=mailto:d@good.com"' }],
  'good.com MX': [{ type: 15, data: '1 aspmx.l.google.com.' }],
  'google._domainkey.good.com TXT': [{ type: 16, data: '"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"' }],
  'bad.com TXT': [{ type: 16, data: '"v=spf1 +all"' }, { type: 16, data: '"v=spf1 -all"' }],
};
export const mockFetch = async url => {
  const u = new URL(url);
  if (u.hostname === 'rdap.org') return { ok: true, json: async () => ({ events: [{ eventAction: 'registration', eventDate: u.pathname.includes('good') ? '2020-01-01T00:00:00Z' : new Date(Date.now() - 5 * 864e5).toISOString() }] }) };
  const key = `${u.searchParams.get('name')} ${u.searchParams.get('type')}`;
  return { ok: true, json: async () => ({ Answer: zone[key] || [] }) };
};

test('healthy domain scores 100', async () => {
  const r = await checkDomain('https://www.good.com/path', { fetchImpl: mockFetch });
  assert.equal(r.domain, 'good.com');
  assert.equal(r.score, 100);
  assert.equal(r.grade, 'Healthy');
  assert.equal(r.checks.mx.provider, 'Google Workspace');
});
test('broken domain is critical', async () => {
  const r = await checkDomain('bad.com', { fetchImpl: mockFetch });
  assert.equal(r.grade, 'Critical');
  assert.equal(r.checks.spf.status, 'fail');
  assert.equal(r.checks.dmarc.status, 'fail');
  assert.equal(r.checks.age.status, 'fail');
});
test('spf and dmarc edge cases', () => {
  assert.equal(analyzeSpf(['v=spf1 include:a ~all']).status, 'pass');
  assert.equal(analyzeSpf(['v=spf1 include:a']).status, 'warn');
  assert.equal(analyzeDmarc(['v=DMARC1; p=none']).status, 'warn');
  assert.equal(analyzeDmarc(['v=DMARC1; p=reject; rua=mailto:x@y.z']).status, 'pass');
  assert.equal(normalizeDomain('Sales@Acme.IO'), 'acme.io');
});
test('invalid input returns an error', async () => {
  assert.ok((await checkDomain('not a domain', { fetchImpl: mockFetch })).error);
});
