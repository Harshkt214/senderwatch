# Senderwatch

Daily health checks for cold email sending domains (SPF, DKIM, DMARC, MX, domain age), with Slack alerts when something gets worse.

## What's here
| File | What it does |
|---|---|
| `index.html` | Landing page with a working free checker (lead magnet), pricing and waitlist |
| `checks.js` | Check engine, shared by the page and the monitor. Uses DNS-over-HTTPS, so no server or API keys |
| `monitor.js` | Daily job: reads `domains.txt`, compares with yesterday (`state.json`), posts changes to Slack |
| `.github/workflows/daily-check.yml` | Runs the monitor every day for free on GitHub Actions |
| `test.js` | Unit tests with a mocked DNS (`npm test`) |

## Launch the site (10 minutes)
1. Create a free form on Formspree or Tally, and paste its endpoint into `WAITLIST_ENDPOINT` in `index.html`.
2. Deploy the folder to Netlify, Vercel or Cloudflare Pages (drag and drop works). Local preview: `npm run dev`.

## Run monitoring for a paying client (concierge MVP)
1. Put their domains in `domains.txt` (`domain  Client name`).
2. Push this folder to a private GitHub repo and add a `SLACK_WEBHOOK_URL` secret (the client's Slack incoming webhook).
3. The workflow runs daily at 03:17 UTC. Run it on demand from the Actions tab.

## Next features, in order of what agencies will pay for
1. Blocklist checks (Spamhaus DQS key, Barracuda, SpamCop). Needs a server-side resolver, because public resolvers are refused.
2. Instantly and Smartlead API import, plus campaign bounce and reply rate per domain.
3. Google Postmaster Tools API (domain reputation, spam rate).
4. White-label weekly PDF report for each client.
5. Self-serve accounts and Stripe billing, once 5+ customers are paying.
