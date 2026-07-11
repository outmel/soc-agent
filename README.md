# SOC Agent

A Slack agent that turns raw security alerts into triaged, enriched, routed incidents — and answers questions about them in plain English.

Security teams drown in alerts. Most are noise, but the dangerous ones need context (is this IP known-bad? has it hit us before?) and speed. SOC Agent does the first 15 minutes of analyst work automatically, inside Slack, in seconds.

## What it does

When an alert arrives (from Splunk, GitHub, or the `/simulate-alert` command):

1. **Enriches** the source IP against VirusTotal and AbuseIPDB in parallel — detection counts, abuse confidence, Tor exit status, ISP, geography.
2. **Correlates** it with past incidents from the same IP, using both the in-memory session and Slack's Real-Time Search API to find incidents from previous sessions in message history — so the agent remembers attacks across restarts.
3. **Scores** the incident 0–100 with a deterministic risk model (alert type, asset criticality, threat intel signals, correlation count) that produces an auditable factor breakdown.
4. **Triages** with an LLM (DeepSeek) that receives all of the above and returns severity, category, summary, response playbook, false-positive likelihood, and a routing decision — with the risk score acting as a floor, so a weak model response can never bury a high-evidence incident.
5. **Routes** the incident card to the right channel (`#critical`, `#high`, `#low`, `#general`) with interactive buttons: Acknowledge, Escalate, Close, False Positive. P1s ping the channel.
6. **Fetches the runbook** for the incident category from a remote MCP server — owner team, SLA, and step-by-step playbook, embedded in the card.

Analysts can then **talk to the agent**:

- **AI assistant panel** — open the app in Slack's AI sidebar, get suggested prompts, and ask things like "which incident has the highest risk score?" or "what do we know about 185.220.101.47?". Answers are grounded in live incident data and RTS history search.
- **@mention** the bot in any channel for the same Q&A in a thread.

A **live web dashboard** (token-protected) shows KPI tiles, an expandable incident feed with attack narrative, blast radius, timeline, and playbook — plus a Campaigns view that groups incidents by source IP into attack chains.

## Slack technologies used

- **Slack AI capabilities** — built on the Agents & Assistants surface (`Assistant` class in Bolt): suggested prompts, thread titles, live status while investigating.
- **Real-Time Search API** — `search.messages` powers cross-session incident correlation and the Q&A engine's history lookups.
- **MCP server integration** — runbooks are served by a separate MCP server over HTTP (`get_playbook` tool), keeping response procedures decoupled from the agent.

## Architecture

![Architecture](docs/architecture.svg)

Webhooks land on the Express receiver (shared with Bolt), pass a shared-secret / HMAC check, and enter the pipeline: enrichment, correlation, scoring, LLM triage, routing. Incidents persist to a JSON file so they survive restarts; the counter, correlation, and dashboard all read from the same store. The dashboard and Q&A API are served by the same process.

## Running it

```
npm install
npm start
```

Copy `.env.example` to `.env` and fill it in. The app needs:

| Variable | Purpose |
|---|---|
| `SLACK_BOT_TOKEN` | Bot token (`xoxb-`) |
| `SLACK_SIGNING_SECRET` | Request signature verification |
| `SLACK_USER_TOKEN` | User token (`xoxp-`) with `search:read` — enables RTS correlation (optional) |
| `DEEPSEEK_API_KEY` | LLM triage and Q&A |
| `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` | Threat intel enrichment |
| `SLACK_CHANNEL_ID` | Default channel for incoming alerts |
| `SLACK_CHANNEL_P1` / `_P2` / `_P3` / `_GENERAL` | Severity-routed channels |
| `SPLUNK_WEBHOOK_SECRET` | Auth for `POST /webhook/splunk` (header `x-webhook-token` or `?token=`) |
| `GITHUB_WEBHOOK_SECRET` | HMAC verification for `POST /webhook/github` |
| `DASHBOARD_TOKEN` | Access token for the dashboard and API |
| `PORT` | Set by the host platform; defaults to 3000 |
| `DATA_DIR` | Where `incidents.json` lives; mount a volume in production |

Slack app configuration: enable **Agents & AI Apps**, subscribe to the `assistant_thread_started`, `assistant_thread_context_changed`, `message.im`, and `app_mention` bot events at `/slack/events`, and grant the scopes listed in `.env.example`. Slash commands: `/simulate-alert`, `/soc-stats`.

## Deployment

The live instance runs on Railway and auto-deploys from this repo's `main` branch. Any Node host works: set the environment variables above, make sure the platform's assigned `PORT` is used (Railway injects it), and mount a persistent volume for `DATA_DIR` if incidents should survive redeploys. Point every Slack request URL (slash commands, event subscriptions, interactivity) at `https://<your-domain>/slack/events`, and remember Splunk 9+ requires the webhook URL to be added to its webhook allow list.

## Demo walkthrough

1. Run `/simulate-alert` — watch the alert get enriched, scored, and routed to a severity channel within seconds.
2. Open the incident card: risk factor breakdown, threat intel, correlated incidents, runbook, response playbook.
3. Fire a second alert from the same IP (Splunk webhook) — the new card links the prior incident and flags a possible campaign.
4. Click Escalate — the incident moves up a channel, severity syncs, the old thread is retired.
5. Open the AI assistant panel and ask: "Are any source IPs behind multiple incidents?"
6. Open the dashboard — Campaigns view shows the attack chain and blast radius.

## Endpoints

| Route | What |
|---|---|
| `POST /webhook/splunk` | Splunk alert intake (token-guarded) |
| `POST /webhook/github` | GitHub push intake, flags sensitive filenames (HMAC-verified) |
| `GET /dashboard` | Live console (token-guarded) |
| `GET /api/incidents`, `/api/stats` | Dashboard data (token-guarded) |
| `GET /api/ask?q=...` | The Q&A engine over HTTP (token-guarded) |
