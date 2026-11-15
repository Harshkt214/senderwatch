// Daily monitor: checks every domain in domains.txt, compares with yesterday, alerts Slack on changes.
// Usage: SLACK_WEBHOOK_URL=https://hooks.slack.com/... node monitor.js [domains.txt]
import { readFile, writeFile } from 'node:fs/promises';
import { checkDomain, CHECK_LABELS } from './checks.js';

const listFile = process.argv[2] || 'domains.txt';
const stateFile = 'state.json';
const webhook = process.env.SLACK_WEBHOOK_URL;

const lines = (await readFile(listFile, 'utf8')).split('\n').map(l => l.replace(/#.*/, '').trim()).filter(Boolean);
// Each line: domain [client name]
const targets = lines.map(l => { const [domain, ...rest] = l.split(/\s+/); return { domain, client: rest.join(' ') || '-' }; });

let prev = {};
try { prev = JSON.parse(await readFile(stateFile, 'utf8')); } catch {}

const results = [];
for (let i = 0; i < targets.length; i += 5) {
  results.push(...await Promise.all(targets.slice(i, i + 5).map(async t => ({ ...t, ...(await checkDomain(t.domain)) }))));
}

const alerts = [];
for (const r of results) {
  if (r.error) { alerts.push(`:grey_question: *${r.domain}* (${r.client}): ${r.error}`); continue; }
  const before = prev[r.domain];
  const broken = Object.entries(r.checks).filter(([k, c]) => c.status === 'fail' && before?.checks?.[k]?.status !== 'fail');
  const dropped = before && r.score <= before.score - 10;
  if (!before && r.grade !== 'Healthy') alerts.push(`:warning: *${r.domain}* (${r.client}) starts at ${r.score}/100, ${r.grade}.`);
  for (const [k, c] of broken) alerts.push(`:rotating_light: *${r.domain}* (${r.client}): ${CHECK_LABELS[k]} failing. ${c.detail}`);
  if (dropped && broken.length === 0) alerts.push(`:chart_with_downwards_trend: *${r.domain}* (${r.client}) fell from ${before.score} to ${r.score}.`);
}

const nextState = Object.fromEntries(results.filter(r => !r.error).map(r => [r.domain, r]));
await writeFile(stateFile, JSON.stringify(nextState, null, 2));

const healthy = results.filter(r => r.grade === 'Healthy').length;
const summary = `Senderwatch daily: ${healthy}/${results.length} domains healthy.`;
console.log(summary);
for (const r of results) console.log(`${String(r.score ?? '--').padStart(3)}  ${(r.grade || 'error').padEnd(8)} ${r.domain}  ${r.client}`);
alerts.forEach(a => console.log(a));

if (webhook && alerts.length) {
  const res = await fetch(webhook, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text: [summary, ...alerts].join('\n') }) });
  if (!res.ok) { console.error(`Slack webhook returned ${res.status}`); process.exitCode = 1; }
}
