// Senderwatch check engine. Runs in the browser (landing page) and in Node 18+ (daily monitor).
// Uses DNS-over-HTTPS so it needs no server and no API keys.

const DOH = [
  (n, t) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}`,
  (n, t) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}`,
];

// Common DKIM selectors: Google Workspace, Microsoft 365, and the usual ESP / cold-email defaults.
export const DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'default', 'k1', 's1', 's2', 'mail', 'dkim', 'smtp', 'zoho', 'mxvault'];

export async function dohQuery(name, type, fetchImpl = globalThis.fetch) {
  let lastErr;
  for (const url of DOH) {
    try {
      const res = await fetchImpl(url(name, type), { headers: { accept: 'application/dns-json' } });
      if (!res.ok) throw new Error(`DoH ${res.status}`);
      const json = await res.json();
      return (json.Answer || []).map(a => ({ type: a.type, data: String(a.data) }));
    } catch (e) { lastErr = e; }
  }
  throw lastErr || new Error('DNS lookup failed');
}

const txt = answers => answers.filter(a => a.type === 16).map(a => a.data.replace(/"\s*"/g, '').replace(/^"|"$/g, ''));

export function normalizeDomain(input) {
  return String(input).trim().toLowerCase()
    .replace(/^[a-z]+:\/\//, '').replace(/^.*@/, '').replace(/^www\./, '').split(/[/?#\s]/)[0];
}

export function analyzeSpf(records) {
  const spf = records.filter(r => /^v=spf1(\s|$)/i.test(r));
  if (spf.length === 0) return { status: 'fail', points: 0, detail: 'No SPF record. Receivers cannot tell which servers may send for you.' };
  if (spf.length > 1) return { status: 'fail', points: 5, detail: `${spf.length} SPF records found. Only one is allowed, so all of them fail.`, record: spf.join(' | ') };
  const rec = spf[0];
  const lookups = (rec.match(/\b(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)/gi) || []).length;
  if (/[+?]all\b/i.test(rec) || !/all\b|redirect=/i.test(rec)) return { status: 'warn', points: 12, detail: 'SPF ends without ~all or -all, so it does not reject spoofed mail.', record: rec };
  if (lookups > 10) return { status: 'fail', points: 8, detail: `About ${lookups} DNS lookups. Over 10 makes SPF permerror.`, record: rec };
  if (lookups > 8) return { status: 'warn', points: 18, detail: `${lookups} top-level lookups. Close to the limit of 10 once includes expand.`, record: rec };
  return { status: 'pass', points: 25, detail: `Valid, ${lookups} top-level lookup${lookups === 1 ? '' : 's'}.`, record: rec };
}

export function analyzeDmarc(records) {
  const rec = records.find(r => /^v=DMARC1/i.test(r));
  if (!rec) return { status: 'fail', points: 0, detail: 'No DMARC record. Gmail, Yahoo and Outlook require one for bulk senders.' };
  const tag = k => (rec.match(new RegExp(`(?:^|;)\\s*${k}=([^;]+)`, 'i')) || [])[1]?.trim().toLowerCase();
  const p = tag('p'), rua = tag('rua');
  if (!p) return { status: 'fail', points: 5, detail: 'DMARC record is missing a p= policy.', record: rec };
  if (p === 'none') return { status: 'warn', points: 15, detail: `Policy is p=none. It passes provider checks but protects nothing.${rua ? '' : ' No rua reports set.'}`, record: rec };
  return { status: 'pass', points: 25, detail: `Policy p=${p}${rua ? ', reports enabled' : ', no rua reports'}.`, record: rec };
}

export function analyzeDkim(found) {
  if (found.length === 0) return { status: 'warn', points: 5, detail: `No key on ${DKIM_SELECTORS.length} common selectors. If you use a custom selector, add it to your watchlist.` };
  return { status: 'pass', points: 25, detail: `Key published on: ${found.join(', ')}.` };
}

export function analyzeMx(answers) {
  const hosts = answers.filter(a => a.type === 15).map(a => a.data.split(/\s+/).pop().replace(/\.$/, '').toLowerCase());
  if (hosts.length === 0) return { status: 'fail', points: 0, detail: 'No MX record. Replies and bounces have nowhere to go, which hurts reputation.' };
  const provider = hosts.some(h => h.includes('google')) ? 'Google Workspace'
    : hosts.some(h => h.includes('outlook') || h.includes('protection.outlook')) ? 'Microsoft 365'
    : hosts.some(h => h.includes('zoho')) ? 'Zoho' : 'Custom';
  return { status: 'pass', points: 15, detail: `${provider} (${hosts[0]}${hosts.length > 1 ? ` +${hosts.length - 1}` : ''}).`, provider };
}

export function analyzeAge(registeredIso, now = Date.now()) {
  if (!registeredIso) return { status: 'unknown', points: 5, detail: 'Registration date not available for this TLD.' };
  const days = Math.floor((now - Date.parse(registeredIso)) / 864e5);
  if (days < 14) return { status: 'fail', points: 0, days, detail: `${days} days old. Send warm-up traffic only.` };
  if (days < 45) return { status: 'warn', points: 5, days, detail: `${days} days old. Keep volume under 20 a day per inbox.` };
  return { status: 'pass', points: 10, days, detail: `${days} days old.` };
}

async function rdapCreated(domain, fetchImpl) {
  try {
    const res = await fetchImpl(`https://rdap.org/domain/${domain}`);
    if (!res.ok) return null;
    const j = await res.json();
    return (j.events || []).find(e => e.eventAction === 'registration')?.eventDate || null;
  } catch { return null; }
}

export function grade(score) {
  return score >= 85 ? 'Healthy' : score >= 60 ? 'At risk' : 'Critical';
}

export async function checkDomain(rawDomain, { fetchImpl = globalThis.fetch, selectors = DKIM_SELECTORS } = {}) {
  const domain = normalizeDomain(rawDomain);
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain)) return { domain, error: 'Not a valid domain' };
  const q = (n, t) => dohQuery(n, t, fetchImpl).catch(() => null);
  const [root, dmarc, mx, created, ...dkim] = await Promise.all([
    q(domain, 'TXT'), q(`_dmarc.${domain}`, 'TXT'), q(domain, 'MX'), rdapCreated(domain, fetchImpl),
    ...selectors.map(s => q(`${s}._domainkey.${domain}`, 'TXT')),
  ]);
  if (root === null && mx === null) return { domain, error: 'DNS lookup failed. Check your connection and try again.' };
  const dkimFound = selectors.filter((s, i) => dkim[i] && txt(dkim[i]).some(r => /(^|;)\s*p=[A-Za-z0-9+/]{20,}/.test(r)));
  const checks = {
    spf: analyzeSpf(txt(root || [])),
    dkim: analyzeDkim(dkimFound),
    dmarc: analyzeDmarc(txt(dmarc || [])),
    mx: analyzeMx(mx || []),
    age: analyzeAge(created),
  };
  const score = Object.values(checks).reduce((s, c) => s + c.points, 0);
  return { domain, score, grade: grade(score), checks, checkedAt: new Date().toISOString() };
}

export const CHECK_LABELS = { spf: 'SPF', dkim: 'DKIM', dmarc: 'DMARC', mx: 'MX', age: 'Domain age' };
