if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}
const { App, ExpressReceiver, Assistant } = require('@slack/bolt');
const { WebClient } = require('@slack/web-api');
const OpenAI = require('openai');
const axios = require('axios');
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const receiver = new ExpressReceiver({
  signingSecret: process.env.SLACK_SIGNING_SECRET
});

// Keep the raw body around so GitHub webhook signatures can be verified.
receiver.app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));
receiver.app.use(express.urlencoded({ extended: true }));

const app = new App({
  token: process.env.SLACK_BOT_TOKEN,
  receiver
});

// Slack search API is user-scoped (xoxp-). Requires `search:read` scope.
const searchClient = process.env.SLACK_USER_TOKEN
  ? new WebClient(process.env.SLACK_USER_TOKEN)
  : null;

const deepseek = new OpenAI({
  baseURL: 'https://api.deepseek.com',
  apiKey: process.env.DEEPSEEK_API_KEY,
});

const activeIncidents = {};

// Monotonic incident counter — random 4-digit IDs collide once you have a
// few dozen incidents. Seeded from persisted incidents on load.
let incidentCounter = 1000;

function nextIncidentId() {
  return ++incidentCounter;
}

// Persistence: incidents survive restarts via a JSON file on disk.
// Set DATA_DIR to a mounted volume (e.g. Railway volume) to persist
// across redeploys; defaults to ./data next to this file.
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'incidents.json');

function saveIncidents() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = `${DATA_FILE}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(activeIncidents));
    fs.renameSync(tmp, DATA_FILE); // atomic replace
  } catch (err) {
    console.error('Failed to persist incidents:', err.message);
  }
}

function loadIncidents() {
  try {
    if (!fs.existsSync(DATA_FILE)) return;
    const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    Object.assign(activeIncidents, parsed);
    for (const i of Object.values(parsed)) {
      const id = Number(i.incidentId);
      if (id > incidentCounter) incidentCounter = id;
    }
    console.log(`Restored ${Object.keys(parsed).length} incident(s) from ${DATA_FILE}`);
  } catch (err) {
    console.error('Failed to load incidents:', err.message);
  }
}

// Public URL for the dashboard, used in Slack messages. Includes the access
// token when one is configured so the link works out of the box.
function dashboardUrl() {
  const base = process.env.PUBLIC_URL
    || (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : null)
    || `http://localhost:${process.env.PORT || 3000}`;
  const token = process.env.DASHBOARD_TOKEN;
  return `${base.replace(/\/$/, '')}/dashboard${token ? `?token=${encodeURIComponent(token)}` : ''}`;
}

const ALERT_SCENARIOS = [
  {
    type: 'Brute Force Attempt',
    source_ip: '185.220.101.47',
    target: 'auth-service-prod',
    detail: '847 failed SSH login attempts in 60 seconds'
  },
  {
    type: 'Malware Hash Detected',
    source_ip: '10.0.1.55',
    target: 'workstation-finance-03',
    detail: 'File hash matches known ransomware: d41d8cd98f00b204e9800998ecf8427e'
  },
  {
    type: 'Data Exfiltration Spike',
    source_ip: '192.168.1.102',
    target: 'database-prod',
    detail: 'Outbound transfer 4.2GB in 3 minutes to external IP 91.108.4.1'
  },
  {
    type: 'Port Scan Detected',
    source_ip: '45.33.32.156',
    target: 'network-perimeter',
    detail: 'Sequential scan across 3200 ports in 30 seconds'
  }
];

function getChannelForRoute(route) {
  const normalized = (route || '').trim().toLowerCase();
  const map = {
    critical: process.env.SLACK_CHANNEL_P1,
    high: process.env.SLACK_CHANNEL_P2,
    low: process.env.SLACK_CHANNEL_P3,
    general: process.env.SLACK_CHANNEL_GENERAL
  };

  const channel = map[normalized] || process.env.SLACK_CHANNEL_ID;

  if (!channel) {
    console.error(`No channel found for route "${route}" — check Railway env vars!`);
  }

  return channel;
}

// Escalation ladder: an incident can be manually bumped one level up.
const ROUTE_ORDER = ['general', 'low', 'high', 'critical'];

// Each routing level corresponds to a priority — escalating raises severity to match.
const ROUTE_SEVERITY = { critical: 'P1', high: 'P2', low: 'P3', general: 'P4' };
const SEVERITY_RANK = { P1: 1, P2: 2, P3: 3, P4: 4 };

function nextRouteUp(route) {
  const idx = ROUTE_ORDER.indexOf((route || 'general').toLowerCase());
  return idx >= 0 && idx < ROUTE_ORDER.length - 1 ? ROUTE_ORDER[idx + 1] : null;
}

async function enrichIP(ip) {
  try {
    const response = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
    });
    const data = response.data.data.attributes;
    const stats = data.last_analysis_stats;
    const total = Object.values(stats).reduce((a, b) => a + b, 0);
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    return {
      malicious,
      suspicious,
      total,
      country: data.country || 'Unknown',
      owner: data.as_owner || 'Unknown',
      reputation: data.reputation || 0,
      flagged: malicious > 0 || suspicious > 0
    };
  } catch (err) {
    console.error('VirusTotal error:', err.message);
    return null;
  }
}

async function enrichIPAbuse(ip) {
  try {
    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      headers: {
        'Key': process.env.ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
      },
      params: {
        ipAddress: ip,
        maxAgeInDays: 90,
        verbose: true
      }
    });
    const data = response.data.data;
    return {
      abuseScore: data.abuseConfidenceScore,
      totalReports: data.totalReports,
      lastReported: data.lastReportedAt ? data.lastReportedAt.substring(0, 10) : 'Never',
      isp: data.isp,
      usageType: data.usageType,
      domain: data.domain,
      isTor: data.isTor,
      isVpn: data.isPublic
    };
  } catch (err) {
    console.error('AbuseIPDB error:', err.message);
    return null;
  }
}

// RTS search function: Slack search API is user-scoped and requires xoxp- token.
async function searchPastIncidentsRTS(sourceIp) {
  if (!searchClient) return [];

  try {
    const results = await searchClient.search.messages({
      query: `"${sourceIp}"`,
      count: 10,
      sort: 'timestamp',
      sort_dir: 'desc'
    });

    const matches = results.messages?.matches || [];

    // Filter to only our own incident messages, exclude the message that's currently being created
    const incidentMatches = matches.filter(m =>
      m.text && m.text.includes('INCIDENT #') && m.text.includes(sourceIp)
    );

    return incidentMatches.map(m => ({
      id: m.text.match(/INCIDENT #(\d+)/)?.[1] || '?',
      text: m.text,
      // Parent messages read "*INCIDENT #id* — P1 | <type> | STATUS"
      type: m.text.match(/\|\s*([^|]+?)\s*\|/)?.[1]?.replace(/\(linked[^)]*\)/, '').trim() || 'Unknown',
      timestamp: new Date(parseFloat(m.ts) * 1000).toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
      channel: m.channel?.name || m.channel?.id,
      permalink: m.permalink,
      source: 'rts_search'
    }));
  } catch (err) {
    const msg = err?.message || String(err);
    console.error('RTS search error:', msg);
    return [];
  }
}

async function getRunbook(category, context = {}) {
  try {
    const response = await axios.post('https://soc-mcp-server-production.up.railway.app/mcp/get_playbook', {
      category,
      context
    });
    return response.data;
  } catch (err) {
    console.error('MCP error:', err.message);
    return null;
  }
}

async function findRelatedOffenses(sourceIp, currentIncidentId) {
  // In-memory correlation (current session)
  const memoryRelated = Object.values(activeIncidents).filter(incident =>
    incident.scenario.source_ip === sourceIp &&
    incident.incidentId !== currentIncidentId
  );

  // RTS search (real Slack history, survives restarts)
  const rtsResults = await searchPastIncidentsRTS(sourceIp);

  const memoryFormatted = memoryRelated.map(i => ({
    id: i.incidentId,
    type: i.scenario.type,
    severity: i.triage.severity,
    target: i.scenario.target,
    timestamp: i.timestamp,
    status: i.status,
    source: 'session'
  }));

  const rtsFormatted = rtsResults.map(r => ({
    id: r.id,
    type: r.type,
    severity: undefined,
    target: undefined,
    timestamp: r.timestamp,
    status: 'historical',
    source: 'rts_search',
    channel: r.channel,
    permalink: r.permalink
  }));

  // Dedupe by incident id, prefer session data (more complete) over RTS
  const seenIds = new Set(memoryFormatted.map(i => String(i.id)));
  const combined = [
    ...memoryFormatted,
    ...rtsFormatted.filter(r => !seenIds.has(String(r.id)))
  ];

  if (combined.length === 0) return null;

  combined.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  return {
    count: combined.length,
    incidents: combined,
    foundViaRTS: rtsFormatted.length > 0
  };
}


// Deterministic risk scoring (0-100), computed from enrichment signals before
// the LLM runs. The score gives the model an evidence-based baseline, sets a
// routing floor (the model can route higher, never lower), and produces a
// factor breakdown analysts can audit.
const TYPE_WEIGHTS = [
  { pattern: /malware|ransom/i,               points: 20, label: 'Malware indicators' },
  { pattern: /exfil/i,                        points: 20, label: 'Data exfiltration pattern' },
  { pattern: /brute force/i,                  points: 15, label: 'Brute force pattern' },
  { pattern: /suspicious file|secret|credential/i, points: 15, label: 'Possible credential exposure' },
  { pattern: /scan|recon/i,                   points: 10, label: 'Reconnaissance pattern' }
];

const ASSET_WEIGHTS = [
  { pattern: /prod|database|\bdb\b/i,   points: 10, label: 'Production or database asset targeted' },
  { pattern: /finance|payroll|auth/i,   points: 8,  label: 'Sensitive business asset targeted' }
];

function computeRiskScore(scenario, vtData, abuseData, correlationData) {
  const factors = [];
  const add = (points, label) => { if (points > 0) factors.push({ points, label }); };

  const typeMatch = TYPE_WEIGHTS.find(t => t.pattern.test(scenario.type || ''));
  add(typeMatch ? typeMatch.points : 8, typeMatch ? typeMatch.label : 'Uncategorized alert type');

  const assetMatch = ASSET_WEIGHTS.find(a => a.pattern.test(scenario.target || ''));
  if (assetMatch) add(assetMatch.points, assetMatch.label);

  if (vtData) {
    if (vtData.malicious > 0) {
      add(Math.min(30, 10 + vtData.malicious * 2), `VirusTotal: ${vtData.malicious} engine(s) flag IP as malicious`);
    } else if (vtData.suspicious > 0) {
      add(5, `VirusTotal: ${vtData.suspicious} engine(s) flag IP as suspicious`);
    }
  }

  if (abuseData) {
    add(Math.round((abuseData.abuseScore || 0) / 4), `AbuseIPDB confidence ${abuseData.abuseScore}% (${abuseData.totalReports} reports)`);
    if (abuseData.isTor) add(10, 'Source is a Tor exit node');
  }

  if (correlationData && correlationData.count > 0) {
    add(Math.min(25, 10 + correlationData.count * 5), `${correlationData.count} correlated incident(s) from the same IP`);
  }

  const score = Math.min(100, factors.reduce((sum, f) => sum + f.points, 0));
  return { score, factors };
}

// Minimum routing level the evidence demands, regardless of what the LLM says.
function riskFloorRoute(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'low';
  return 'general';
}

// Attach the risk assessment to the triage result and enforce the routing
// floor. Severity is raised to match the route when the floor kicks in,
// mirroring how manual escalation keeps the two in sync.
function applyRiskAssessment(triage, risk) {
  triage.riskScore = risk.score;
  triage.riskFactors = risk.factors;

  const floor = riskFloorRoute(risk.score);
  if (ROUTE_ORDER.indexOf(floor) > ROUTE_ORDER.indexOf(triage.route)) {
    triage.route = floor;
    triage.routeReason = `${(triage.routeReason || '').trim()} · Raised to ${floor.toUpperCase()} by risk score ${risk.score}/100`;
    const sevTarget = ROUTE_SEVERITY[floor];
    if (sevTarget && (SEVERITY_RANK[sevTarget] || 9) < (SEVERITY_RANK[triage.severity] || 9)) {
      triage.severity = sevTarget;
    }
  }
}

async function triageAlert(alert, vtData, abuseData, correlationData, risk) {
  const correlationContext = correlationData
    ? `\nCORRELATED ACTIVITY:
This source IP has ${correlationData.count} other recent incident(s) from the same source:
${correlationData.incidents.map(i => `- ${i.type} targeting ${i.target} (${i.severity}) at ${i.timestamp}`).join('\n')}

This suggests a potential multi-stage attack campaign rather than an isolated event. Factor this into your severity and confidence assessment.`
    : '';

  const prompt = `You are a senior SOC analyst at a Fortune 500 company.

ALERT:
Type: ${alert.type}
Source IP: ${alert.source_ip}
Target: ${alert.target}
Detail: ${alert.detail}

THREAT INTELLIGENCE:
- VirusTotal: ${vtData ? `${vtData.malicious}/${vtData.total} engines flagged` : 'unavailable'}
- Country: ${vtData?.country || 'unknown'}
- Owner: ${vtData?.owner || 'unknown'}
- Reputation score: ${vtData?.reputation || 'unknown'}
- Threat level: ${vtData?.flagged ? 'FLAGGED AS MALICIOUS' : 'clean'}

AbuseIPDB:
- Abuse confidence: ${abuseData ? `${abuseData.abuseScore}%` : 'unavailable'}
- Total abuse reports: ${abuseData?.totalReports || 0}
- Last reported: ${abuseData?.lastReported || 'never'}
- ISP: ${abuseData?.isp || 'unknown'}
- Usage type: ${abuseData?.usageType || 'unknown'}
- Tor exit node: ${abuseData?.isTor ? 'YES' : 'NO'}
${correlationContext}

DETERMINISTIC RISK SCORE: ${risk.score}/100, computed from the signals above:
${risk.factors.map(f => `- ${f.label} (+${f.points})`).join('\n')}
Use this score as your baseline for severity and routing. Deviate only when the evidence justifies it, and explain why in route_reason.

Based on ALL of this context respond with a single JSON object using exactly these keys:
{
  "severity": "P1, P2, P3 or P4",
  "category": "Brute Force, Malware, Data Exfiltration, Reconnaissance or Other",
  "confidence": "High, Medium or Low",
  "summary": "2-3 sentences explaining exactly what is happening and why it matters",
  "immediate_action": "specific step to take in the next 5 minutes",
  "short_term_action": "what to do in the next hour",
  "long_term_action": "what to fix to prevent recurrence",
  "false_positive_chance": "percentage with brief reasoning",
  "escalate_to": "which team should be notified",
  "route": "critical, high, low or general",
  "route_reason": "1 sentence explaining why this routing destination was chosen"
}

Notes:
- route must reflect actual risk and urgency, not just the severity label.
- If route is critical, the incident requires immediate all-hands attention.

Available routing destinations:
- critical — immediate, all-hands attention (active breach/high-confidence malicious activity/multi-stage campaign in progress)
- high — serious incident requiring prompt investigation
- low — lower-priority anomalies/unconfirmed suspicious activity
- general — informational/routine/likely false positives`;

  const response = await deepseek.chat.completions.create({
    model: 'deepseek-chat',
    messages: [{ role: 'user', content: prompt }],
    response_format: { type: 'json_object' }
  });
  return response.choices[0].message.content;
}

const VALID_SEVERITIES = ['P1', 'P2', 'P3', 'P4'];
const VALID_ROUTES = ['critical', 'high', 'low', 'general'];

function parseTriageResult(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Triage response was not valid JSON: ${String(raw).slice(0, 200)}`);
  }

  const field = (key, fallback = 'Unknown') => {
    const value = parsed[key];
    return typeof value === 'string' && value.trim() ? value.trim() : fallback;
  };

  const severity = field('severity').toUpperCase();
  const route = field('route', 'general').toLowerCase();
  if (!VALID_SEVERITIES.includes(severity)) {
    console.warn(`Triage returned unexpected severity "${severity}", defaulting to P3`);
  }
  if (!VALID_ROUTES.includes(route)) {
    console.warn(`Triage returned unexpected route "${route}", defaulting to general`);
  }

  return {
    severity: VALID_SEVERITIES.includes(severity) ? severity : 'P3',
    category: field('category'),
    confidence: field('confidence'),
    summary: field('summary'),
    immediateAction: field('immediate_action'),
    shortTermAction: field('short_term_action'),
    longTermAction: field('long_term_action'),
    falsePositive: field('false_positive_chance'),
    escalateTo: field('escalate_to'),
    route: VALID_ROUTES.includes(route) ? route : 'general',
    routeReason: field('route_reason', 'No routing reason provided')
  };
}


const SEVERITY_META = {
  P1:      { color: '#E01E5A', label: 'CRITICAL' },
  P2:      { color: '#F5871F', label: 'HIGH' },
  P3:      { color: '#ECB22E', label: 'MEDIUM' },
  P4:      { color: '#2EB67D', label: 'LOW' },
  default: { color: '#8D8D8D', label: 'UNKNOWN' }
};

const STATUS_META = {
  open:   { label: 'OPEN',           blurb: 'Awaiting response' },
  ack:    { label: 'ACKNOWLEDGED',   blurb: 'Being investigated' },
  closed: { label: 'CLOSED',         blurb: 'Resolved' },
  fp:     { label: 'FALSE POSITIVE', blurb: 'Dismissed' }
};

// Renders an incident as a Slack Block Kit card (top-level blocks).
// Returns a `blocks` array. buildThreadText() is passed as the message `text`,
// which Slack then treats as a hidden notification/search fallback (not rendered),
// so nothing is duplicated and RTS search still finds the source IP in the text.
function buildIncidentBlocks(incidentId, triage, scenario, timestamp, status, closedBy, vtData, runbookData, abuseData, correlationData, incidentTs) {
  const sev = SEVERITY_META[triage.severity] || SEVERITY_META.default;
  const st = STATUS_META[status] || STATUS_META.open;
  const route = (triage.route || 'general').toUpperCase();

  const statusBadge = status === 'closed' || status === 'fp'
    ? `${st.label} · <@${closedBy}>`
    : st.label;

  const blocks = [
    {
      type: 'header',
      text: { type: 'plain_text', text: `INCIDENT #${incidentId} · ${triage.severity} ${triage.category.toUpperCase()}` }
    },
    // Compact status banner: severity · status · time
    {
      type: 'context',
      elements: [
        { type: 'mrkdwn', text: `*${triage.severity} ${sev.label}*` },
        { type: 'mrkdwn', text: statusBadge },
        ...(triage.riskScore != null ? [{ type: 'mrkdwn', text: `Risk ${triage.riskScore}/100` }] : []),
        { type: 'mrkdwn', text: timestamp }
      ]
    },
    { type: 'divider' },
    // Key facts
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*Type*\n${scenario.type}` },
        { type: 'mrkdwn', text: `*Confidence*\n${triage.confidence}` },
        { type: 'mrkdwn', text: `*Source IP*\n\`${scenario.source_ip}\`` },
        { type: 'mrkdwn', text: `*Target*\n\`${scenario.target}\`` },
        { type: 'mrkdwn', text: `*Escalate to*\n${triage.escalateTo}` },
        { type: 'mrkdwn', text: `*Channel routed*\n${route}` }
      ]
    },
    {
      type: 'section',
      text: { type: 'mrkdwn', text: `*Detail*\n${scenario.detail}` }
    },
    { type: 'divider' },
    // Analyst reasoning
    {
      type: 'section',
      text: { type: 'mrkdwn', text: `*Routing Decision — ${route}*\n${(triage.routeReason || 'No reason provided').trim()}` }
    },
    {
      type: 'section',
      text: { type: 'mrkdwn', text: `*False-Positive Likelihood*\n${triage.falsePositive}` }
    },
    { type: 'divider' },
    // Threat intelligence
    {
      type: 'section',
      text: { type: 'mrkdwn', text: '*Threat Intelligence*' }
    }
  ];

  // Threat intelligence (VirusTotal + AbuseIPDB side by side)
  const intelFields = [];
  if (vtData) {
    intelFields.push({
      type: 'mrkdwn',
      text: `*VirusTotal*\n${vtData.malicious}/${vtData.total} engines · ${vtData.flagged ? 'Flagged' : 'Clean'}\n${vtData.country} · ${vtData.owner}`
    });
  }
  if (abuseData) {
    const risk = abuseData.abuseScore > 80 ? 'High' : abuseData.abuseScore > 40 ? 'Medium' : 'Low';
    intelFields.push({
      type: 'mrkdwn',
      text: `*AbuseIPDB*\n${abuseData.abuseScore}% abuse · ${risk} risk\n${abuseData.totalReports} reports · ${abuseData.isTor ? 'Tor exit' : 'No Tor'}`
    });
  }
  if (intelFields.length) {
    blocks.push({ type: 'section', fields: intelFields });
  }

  // Risk score breakdown — the auditable "why" behind severity and routing
  if (triage.riskScore != null && Array.isArray(triage.riskFactors) && triage.riskFactors.length) {
    blocks.push({
      type: 'context',
      elements: [{
        type: 'mrkdwn',
        text: `*Risk score ${triage.riskScore}/100* — ${triage.riskFactors.map(f => `${f.label} (+${f.points})`).join(' · ')}`
      }]
    });
  }

  // Correlation — highlight potential multi-stage campaigns
  if (correlationData && correlationData.count > 0) {
    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*${correlationData.count} correlated incident${correlationData.count > 1 ? 's' : ''} from this IP* — possible multi-stage campaign\n${correlationData.incidents.map(i => `• #${i.id}: ${i.type} → ${i.target || '?'} ${i.severity ? `(${i.severity})` : ''} _[${i.status}]_`).join('\n')}`
      }
    });
  }

  // MCP runbook
  if (runbookData) {
    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*Runbook — ${runbookData.category.toUpperCase()}* · ${runbookData.owner_team} · SLA ${runbookData.sla_minutes}m\n${runbookData.playbook.split('\n').map(s => `• ${s}`).join('\n')}`
      }
    });
  }

  blocks.push({ type: 'divider' });

  // AI triage summary + response actions
  blocks.push(
    {
      type: 'section',
      text: { type: 'mrkdwn', text: `*AI Triage Summary*\n${triage.summary}` }
    },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*Response Playbook*\n*Now (5 min):* ${triage.immediateAction}\n*Soon (1 hr):* ${triage.shortTermAction}\n*Prevent:* ${triage.longTermAction}`
      }
    }
  );

  const actionButtons = buildActionButtons(incidentTs, status, triage.route);
  if (actionButtons.length) {
    blocks.push(...actionButtons);
  } else {
    // No buttons once closed/FP — show a closing status line instead
    blocks.push({
      type: 'context',
      elements: [{ type: 'mrkdwn', text: `*${st.label}*${closedBy ? ` by <@${closedBy}>` : ''} — ${st.blurb}` }]
    });
  }

  return blocks;
}

function buildThreadText(incidentId, triage, scenario, timestamp, status, closedBy, vtData, runbookData, abuseData, correlationData) {
  const statusLine = {
    open:   `*Status:* OPEN`,
    ack:    `*Status:* ACKNOWLEDGED — being investigated`,
    closed: `*Status:* CLOSED — resolved by <@${closedBy}>`,
    fp:     `*Status:* FALSE POSITIVE — dismissed by <@${closedBy}>`
  }[status];

  const vtSection = vtData
    ? `\n*VIRUSTOTAL ENRICHMENT*
- Malicious detections: ${vtData.malicious}/${vtData.total} engines
- Suspicious: ${vtData.suspicious}
- Country: ${vtData.country}
- Owner: ${vtData.owner}
- Reputation score: ${vtData.reputation}
- Threat level: ${vtData.flagged ? 'FLAGGED' : 'CLEAN'}\n`
    : `\n*VIRUSTOTAL ENRICHMENT*\n- Looking up IP...\n`;

  const abuseSection = abuseData
    ? `\n*ABUSEIPDB ENRICHMENT*
- Abuse confidence: ${abuseData.abuseScore}% (${abuseData.abuseScore > 80 ? 'high' : abuseData.abuseScore > 40 ? 'medium' : 'low'} risk)
- Total reports: ${abuseData.totalReports}
- Last reported: ${abuseData.lastReported}
- ISP: ${abuseData.isp}
- Usage type: ${abuseData.usageType}
- Tor exit node: ${abuseData.isTor ? 'YES' : 'No'}\n`
    : '';

  const correlationSection = correlationData && correlationData.count > 0
    ? `\n*CORRELATED INCIDENTS DETECTED*
This source IP has ${correlationData.count} other related incident(s) — possible multi-stage attack campaign
${correlationData.incidents.map(i => `- #${i.id}: ${i.type} → ${i.target} (${i.severity}) at ${i.timestamp} [${i.status}]`).join('\n')}\n`
    : '';

  const runbookSection = runbookData
    ? `\n*MCP RUNBOOK — ${runbookData.category.toUpperCase()}*
- Owner team: ${runbookData.owner_team}
- SLA: Respond within ${runbookData.sla_minutes} minutes
${runbookData.playbook.split('\n').map(s => `- ${s}`).join('\n')}\n`
    : '';

  const riskSection = triage.riskScore != null
    ? `\n*RISK SCORE — ${triage.riskScore}/100*
${(triage.riskFactors || []).map(f => `- ${f.label} (+${f.points})`).join('\n')}\n`
    : '';

  return `*INCIDENT #${incidentId} — ${triage.severity} ${triage.category.toUpperCase()}*
*Type:* ${scenario.type}
*Source:* \`${scenario.source_ip}\`
*Target:* \`${scenario.target}\`
*Time:* ${timestamp}
*Detail:* ${scenario.detail}
${vtSection}${abuseSection}${correlationSection}${riskSection}${runbookSection}
*AI TRIAGE*
- Severity: ${triage.severity}
- Category: ${triage.category}
- Confidence: ${triage.confidence}
- False Positive Chance: ${triage.falsePositive}
- Escalate to: ${triage.escalateTo}
- Routed to: *${(triage.route || 'general').toUpperCase()}* — ${(triage.routeReason || 'No routing reason provided').trim()}

*SUMMARY*
${triage.summary}

*RESPONSE ACTIONS*
- *Immediate (next 5 min):* ${triage.immediateAction}
- *Short-term (next hour):* ${triage.shortTermAction}
- *Long-term (prevent recurrence):* ${triage.longTermAction}

${statusLine}`;
}

function buildActionButtons(incidentTs, status, route) {
  if (status !== 'open' && status !== 'ack') return [];

  const elements = [
    {
      type: 'button',
      text: { type: 'plain_text', text: 'Acknowledge' },
      style: 'primary',
      action_id: 'incident_ack',
      value: incidentTs
    }
  ];

  // Only offer escalation when there is a higher channel to go to
  const upRoute = nextRouteUp(route);
  if (upRoute) {
    elements.push({
      type: 'button',
      text: { type: 'plain_text', text: `Escalate to ${upRoute.toUpperCase()}` },
      action_id: 'incident_escalate',
      value: incidentTs,
      confirm: {
        title: { type: 'plain_text', text: 'Escalate incident?' },
        text: { type: 'mrkdwn', text: `This will move the incident to the *${upRoute.toUpperCase()}* channel and notify that team.` },
        confirm: { type: 'plain_text', text: 'Escalate' },
        deny: { type: 'plain_text', text: 'Cancel' }
      }
    });
  }

  elements.push(
    {
      type: 'button',
      text: { type: 'plain_text', text: 'Close' },
      action_id: 'incident_close',
      value: incidentTs
    },
    {
      type: 'button',
      text: { type: 'plain_text', text: 'False Positive' },
      style: 'danger',
      action_id: 'incident_fp',
      value: incidentTs
    }
  );

  return [
    {
      type: 'actions',
      block_id: `incident_actions_${incidentTs}`,
      elements
    }
  ];
}

async function processAlert(client, channelId, customAlert = null) {
  const scenario = customAlert || ALERT_SCENARIOS[Math.floor(Math.random() * ALERT_SCENARIOS.length)];
  const incidentId = nextIncidentId();
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

  const initial = await client.chat.postMessage({
    channel: channelId,
    text: `*INCOMING ALERT* — AI triage in progress...`,
  });

  try {
    const [vtData, abuseData] = await Promise.all([
      enrichIP(scenario.source_ip),
      enrichIPAbuse(scenario.source_ip)
    ]);

    const correlationData = await findRelatedOffenses(scenario.source_ip, incidentId);
    const risk = computeRiskScore(scenario, vtData, abuseData, correlationData);

    const rawTriageEnriched = await triageAlert(scenario, vtData, abuseData, correlationData, risk);
    const triage = parseTriageResult(rawTriageEnriched);
    applyRiskAssessment(triage, risk);

    const targetChannel = getChannelForRoute(triage.route);

    const runbookData = await getRunbook(triage.category, {
      severity: triage.severity,
      sourceIp: scenario.source_ip,
      target: scenario.target,
      abuseScore: abuseData?.abuseScore || 0,
      isTor: abuseData?.isTor || false,
      usageType: abuseData?.usageType || '',
      maliciousVT: vtData?.malicious || 0,
      country: vtData?.country || '',
      totalReports: abuseData?.totalReports || 0
    });

    await client.chat.update({
      channel: channelId,
      ts: initial.ts,
      text: `*INCIDENT #${incidentId}* — ${triage.severity} | ${scenario.type} | Routed to ${triage.route.toUpperCase()} channel`
    });

    const severityMsg = await client.chat.postMessage({
      channel: targetChannel,
      text: `*INCIDENT #${incidentId}* — ${triage.severity} | ${scenario.type}${correlationData ? ` (linked to ${correlationData.count} prior incident${correlationData.count > 1 ? 's' : ''})` : ''} | OPEN`
    });

    const threadMsg = await client.chat.postMessage({
      channel: targetChannel,
      thread_ts: severityMsg.ts,
      text: buildThreadText(incidentId, triage, scenario, timestamp, 'open', null, vtData, runbookData, abuseData, correlationData),
      blocks: buildIncidentBlocks(incidentId, triage, scenario, timestamp, 'open', null, vtData, runbookData, abuseData, correlationData, severityMsg.ts)
    });

    if (triage.route === 'critical') {
      await client.chat.postMessage({
        channel: targetChannel,
        thread_ts: severityMsg.ts,
        text: `*P1 CRITICAL* — <!channel> This requires immediate attention. Use the Acknowledge button to take ownership.`
      });
    }

    activeIncidents[severityMsg.ts] = {
      channelId: targetChannel,
      threadTs: threadMsg.ts,
      parentTs: severityMsg.ts,
      scenario,
      triage,
      vtData,
      abuseData,
      runbookData,
      correlationData,
      incidentId,
      timestamp,
      status: 'open',
      events: [{ at: timestamp, type: 'created' }]
    };
    saveIncidents();

  } catch (err) {
    console.error('Triage error:', err);
    await client.chat.postMessage({
      channel: channelId,
      thread_ts: initial.ts,
      text: `AI triage failed: ${err.message}`
    });
  }
}

// Auth for inbound webhooks and the dashboard. Each check only kicks in
// when its secret is configured, so local development works without setup —
// startup logs a warning for anything left open.
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function verifySplunkRequest(req) {
  const secret = process.env.SPLUNK_WEBHOOK_SECRET;
  if (!secret) return true;
  const provided = req.headers['x-webhook-token'] || req.query.token;
  return !!provided && safeEqual(provided, secret);
}

function verifyGithubSignature(req) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) return true;
  const signature = req.headers['x-hub-signature-256'];
  if (!signature || !req.rawBody) return false;
  const expected = 'sha256=' + crypto.createHmac('sha256', secret).update(req.rawBody).digest('hex');
  return safeEqual(signature, expected);
}

function requireDashboardToken(req, res, next) {
  const secret = process.env.DASHBOARD_TOKEN;
  if (!secret) return next();
  if (req.query.token && safeEqual(req.query.token, secret)) return next();
  res.sendStatus(401);
}

receiver.app.post('/webhook/splunk', async (req, res) => {
  if (!verifySplunkRequest(req)) {
    console.warn('Rejected /webhook/splunk request: bad or missing token');
    return res.sendStatus(401);
  }
  res.sendStatus(200);

  const payload = req.body;
  console.log('Splunk alert received:', JSON.stringify(payload, null, 2));

  const result = payload.result || payload;
  const srcIp = result.src_ip || 'unknown';
  const dest = result.dest || 'unknown';
  const eventType = result.event_type || 'unknown';
  const severity = result.severity || 'unknown';
  const message = result.message || 'Splunk detected a security event';
  const count = result.count || '1';

  const typeMap = {
    brute_force: 'Brute Force Attempt',
    port_scan: 'Port Scan Detected',
    data_exfil: 'Data Exfiltration Spike',
    malware: 'Malware Hash Detected'
  };

  const alert = {
    type: typeMap[eventType] || 'Splunk Security Alert',
    source_ip: srcIp,
    target: dest,
    detail: `${message} — severity: ${severity}, count: ${count} [via Splunk]`
  };

  const channelId = process.env.SLACK_CHANNEL_ID;
  processAlert(app.client, channelId, alert);
});

receiver.app.post('/webhook/github', async (req, res) => {
  if (!verifyGithubSignature(req)) {
    console.warn('Rejected /webhook/github request: signature verification failed');
    return res.sendStatus(401);
  }
  res.sendStatus(200);

  const event = req.headers['x-github-event'];
  const payload = req.body;
  console.log('GitHub webhook received:', event);

  let alert = null;

  if (event === 'push') {
    const commits = payload.commits || [];
    const suspiciousFiles = commits
      .flatMap(c => [...(c.added || []), ...(c.modified || [])])
      .filter(f => f.match(/\.env|password|secret|credential|private_key/i));

    if (suspiciousFiles.length > 0) {
      alert = {
        type: 'Suspicious File Push',
        source_ip: 'github.com',
        target: payload.repository?.full_name || 'unknown repo',
        detail: `Sensitive filename in push: ${suspiciousFiles.join(', ')} by ${payload.pusher?.name}`
      };
    }
  }

  if (alert) {
    const channelId = process.env.SLACK_CHANNEL_ID;
    processAlert(app.client, channelId, alert);
  }
});

async function handleIncidentAction(actionId, incidentTs, userId, client) {
  const incident = activeIncidents[incidentTs];
  if (!incident) return;

  let newStatus = null;
  if (actionId === 'incident_close') newStatus = 'closed';
  else if (actionId === 'incident_ack') newStatus = 'ack';
  else if (actionId === 'incident_fp') newStatus = 'fp';

  if (!newStatus) return;
  if (incident.status === newStatus) return;

  incident.status = newStatus;
  incident.events = incident.events || [];
  incident.events.push({
    at: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
    type: newStatus,
    by: userId
  });
  saveIncidents();

  const statusLabel = {
    closed: 'CLOSED',
    ack:    'ACKNOWLEDGED',
    fp:     'FALSE POSITIVE'
  }[newStatus];

  await client.chat.update({
    channel: incident.channelId,
    ts: incident.parentTs,
    text: `*INCIDENT #${incident.incidentId}* — ${incident.triage.severity} | ${incident.scenario.type} | ${statusLabel}`
  });

  const updatedText = buildThreadText(
    incident.incidentId,
    incident.triage,
    incident.scenario,
    incident.timestamp,
    newStatus,
    userId,
    incident.vtData,
    incident.runbookData,
    incident.abuseData,
    incident.correlationData
  );

  await client.chat.update({
    channel: incident.channelId,
    ts: incident.threadTs,
    text: updatedText,
    attachments: [],
    blocks: buildIncidentBlocks(
      incident.incidentId,
      incident.triage,
      incident.scenario,
      incident.timestamp,
      newStatus,
      userId,
      incident.vtData,
      incident.runbookData,
      incident.abuseData,
      incident.correlationData,
      incidentTs
    )
  });

  const statusMessages = {
    closed: `Incident closed by <@${userId}>. Marking as resolved.`,
    ack:    `<@${userId}> is on it. Incident acknowledged.`,
    fp:     `Marked as false positive by <@${userId}>. Dismissed.`
  };

  await client.chat.postMessage({
    channel: incident.channelId,
    thread_ts: incident.parentTs,
    text: statusMessages[newStatus]
  });
}

app.action('incident_ack', async ({ ack, body, client }) => {
  await ack();
  await handleIncidentAction('incident_ack', body.actions[0].value, body.user.id, client);
});

app.action('incident_close', async ({ ack, body, client }) => {
  await ack();
  await handleIncidentAction('incident_close', body.actions[0].value, body.user.id, client);
});

app.action('incident_fp', async ({ ack, body, client }) => {
  await ack();
  await handleIncidentAction('incident_fp', body.actions[0].value, body.user.id, client);
});

// Manual escalation: move the incident one channel up the ladder.
async function handleEscalate(incidentTs, userId, client) {
  const incident = activeIncidents[incidentTs];
  if (!incident) return;
  if (incident.status !== 'open' && incident.status !== 'ack') return;

  const fromRoute = (incident.triage.route || 'general').toLowerCase();
  const toRoute = nextRouteUp(fromRoute);
  if (!toRoute) {
    await client.chat.postMessage({
      channel: incident.channelId,
      thread_ts: incident.parentTs,
      text: `<@${userId}> Incident is already in the CRITICAL channel — nowhere higher to escalate.`
    });
    return;
  }

  const newChannel = getChannelForRoute(toRoute);
  const oldChannel = incident.channelId;
  const st = STATUS_META[incident.status] || STATUS_META.open;
  const now = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

  // Update routing + history before re-rendering
  incident.triage.route = toRoute;
  incident.triage.routeReason = `${(incident.triage.routeReason || '').trim()} · Manually escalated from ${fromRoute.toUpperCase()} by analyst`;

  // Raise severity to match the new level (never downgrade) so the
  // dashboard, KPI tiles, and card colors stay in sync with the channel.
  const sevBefore = incident.triage.severity;
  const sevTarget = ROUTE_SEVERITY[toRoute];
  if (sevTarget && (SEVERITY_RANK[sevTarget] || 9) < (SEVERITY_RANK[sevBefore] || 9)) {
    incident.triage.severity = sevTarget;
  }
  const sevRaised = incident.triage.severity !== sevBefore;

  incident.events = incident.events || [];
  incident.events.push({
    at: now, type: 'escalated', by: userId, from: fromRoute, to: toRoute,
    sevFrom: sevBefore, sevTo: incident.triage.severity
  });

  // Re-post the incident in the higher channel
  const newParent = await client.chat.postMessage({
    channel: newChannel,
    text: `*INCIDENT #${incident.incidentId}* — ${incident.triage.severity} | ${incident.scenario.type} | ESCALATED from ${fromRoute.toUpperCase()} | ${st.label}`
  });
  const newThread = await client.chat.postMessage({
    channel: newChannel,
    thread_ts: newParent.ts,
    text: buildThreadText(incident.incidentId, incident.triage, incident.scenario, incident.timestamp, incident.status, null, incident.vtData, incident.runbookData, incident.abuseData, incident.correlationData),
    blocks: buildIncidentBlocks(incident.incidentId, incident.triage, incident.scenario, incident.timestamp, incident.status, null, incident.vtData, incident.runbookData, incident.abuseData, incident.correlationData, newParent.ts)
  });

  if (toRoute === 'critical') {
    await client.chat.postMessage({
      channel: newChannel,
      thread_ts: newParent.ts,
      text: `*ESCALATED TO CRITICAL* — <!channel> <@${userId}> escalated this incident. Immediate attention required.`
    });
  }

  // Mark the old messages as escalated and retire their buttons
  await client.chat.update({
    channel: oldChannel,
    ts: incident.parentTs,
    text: `*INCIDENT #${incident.incidentId}* — ${incident.triage.severity} | ${incident.scenario.type} | ESCALATED to ${toRoute.toUpperCase()}`
  });

  const retiredBlocks = buildIncidentBlocks(incident.incidentId, incident.triage, incident.scenario, incident.timestamp, incident.status, null, incident.vtData, incident.runbookData, incident.abuseData, incident.correlationData, incidentTs)
    .filter(b => b.type !== 'actions');
  retiredBlocks.push({
    type: 'context',
    elements: [{ type: 'mrkdwn', text: `*Escalated to ${toRoute.toUpperCase()}* by <@${userId}> — this thread is retired, follow up in the ${toRoute} channel.` }]
  });
  await client.chat.update({
    channel: oldChannel,
    ts: incident.threadTs,
    text: `Incident #${incident.incidentId} escalated to ${toRoute.toUpperCase()}`,
    attachments: [],
    blocks: retiredBlocks
  });
  await client.chat.postMessage({
    channel: oldChannel,
    thread_ts: incident.parentTs,
    text: `<@${userId}> escalated this incident to the *${toRoute.toUpperCase()}* channel.${sevRaised ? ` Severity raised ${sevBefore} to ${incident.triage.severity}.` : ''}`
  });

  // Move the record under the new parent ts so the new buttons resolve
  incident.channelId = newChannel;
  incident.parentTs = newParent.ts;
  incident.threadTs = newThread.ts;
  activeIncidents[newParent.ts] = incident;
  delete activeIncidents[incidentTs];
  saveIncidents();
}

app.action('incident_escalate', async ({ ack, body, client }) => {
  await ack();
  try {
    await handleEscalate(body.actions[0].value, body.user.id, client);
  } catch (err) {
    console.error('Escalation error:', err.message);
  }
});

app.command('/soc-stats', async ({ ack, client, body }) => {
  await ack();

  (async () => {
    const incidents = Object.values(activeIncidents);

    if (incidents.length === 0) {
      await client.chat.postMessage({
        channel: body.channel_id,
        text: `*SOC DASHBOARD*\nNo incidents recorded yet. Run \`/simulate-alert\` to generate one.\n\n*Live dashboard:* ${dashboardUrl()}`
      });
      return;
    }

    const p1 = incidents.filter(i => i.triage.severity === 'P1').length;
    const p2 = incidents.filter(i => i.triage.severity === 'P2').length;
    const p3 = incidents.filter(i => i.triage.severity === 'P3').length;
    const p4 = incidents.filter(i => i.triage.severity === 'P4').length;
    const open = incidents.filter(i => i.status === 'open').length;
    const acked = incidents.filter(i => i.status === 'ack').length;
    const closed = incidents.filter(i => i.status === 'closed').length;
    const fp = incidents.filter(i => i.status === 'fp').length;
    const fpRate = Math.round((fp / incidents.length) * 100);

    const categories = incidents.reduce((acc, i) => {
      acc[i.triage.category] = (acc[i.triage.category] || 0) + 1;
      return acc;
    }, {});

    const topCategory = Object.entries(categories).sort((a, b) => b[1] - a[1])[0];

    await client.chat.postMessage({
      channel: body.channel_id,
      text: `*SOC DASHBOARD — LIVE SESSION STATS*\n\n*SEVERITY BREAKDOWN*\n- P1 Critical: ${p1}\n- P2 High: ${p2}\n- P3 Medium: ${p3}\n- P4 Low: ${p4}\n- Total: ${incidents.length}\n\n*INCIDENT STATUS*\n- Open: ${open}\n- Acknowledged: ${acked}\n- Closed: ${closed}\n- False Positives: ${fp}\n\n*METRICS*\n- False Positive Rate: ${fpRate}%\n- Top Threat Category: ${topCategory ? topCategory[0] : 'N/A'} (${topCategory ? topCategory[1] : 0} incidents)\n- Resolution Rate: ${Math.round(((closed + fp) / incidents.length) * 100)}%\n\n*Live dashboard:* ${dashboardUrl()}`
    });
  })();
});

app.command('/simulate-alert', async ({ ack, client, body }) => {
  await ack();
  await client.chat.postMessage({
    channel: body.channel_id,
    text: `Alert simulation started — routing to severity channel after triage...`
  });
  processAlert(client, body.channel_id);
});

// Conversational agent: analysts can ask about incidents in the AI assistant
// panel, by mentioning the bot in a channel, or via /api/ask. All three share
// the same answer engine, which grounds DeepSeek in live incident data and
// pulls Slack history via RTS search when the question references an IP.

function incidentBriefing() {
  const list = serializeIncidents().slice(0, 20);
  if (!list.length) return 'No incidents recorded in the current session.';
  return list.map(i =>
    `#${i.id} [${i.severity} ${i.status}] ${i.type} — ${i.sourceIp} -> ${i.target}` +
    ` · risk ${i.riskScore != null ? `${i.riskScore}/100` : 'n/a'} · routed ${i.route}` +
    `${i.correlatedCount ? ` · ${i.correlatedCount} correlated` : ''} · ${i.timestamp}\n  ${i.summary}`
  ).join('\n');
}

async function answerAnalystQuestion(question) {
  // If the question mentions IPs, pull related history from Slack via RTS
  const ips = [...new Set(question.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [])].slice(0, 2);
  const rtsSections = [];
  for (const ip of ips) {
    const hits = await searchPastIncidentsRTS(ip);
    if (hits.length) {
      rtsSections.push(`SLACK HISTORY FOR ${ip} (via Real-Time Search):\n` +
        hits.slice(0, 5).map(h => `- #${h.id} ${h.type} at ${h.timestamp} in #${h.channel}`).join('\n'));
    }
  }

  const prompt = `You are a SOC (Security Operations Center) agent inside Slack. Answer the analyst's question using the live data below. Be concise and factual. If the data does not answer the question, say so plainly rather than guessing.

FORMAT RULES (Slack mrkdwn):
- Start with a one-line direct answer to the question.
- Follow with short bullets starting with "- ". Bold key facts with single *asterisks*.
- Put IPs, hostnames and hashes in \`backticks\`. Reference incidents as *#1001*.
- No markdown headers, no tables, no ** double asterisks.
- Keep it under 120 words unless the question genuinely needs more.

CURRENT INCIDENTS (newest first):
${incidentBriefing()}
${rtsSections.length ? '\n' + rtsSections.join('\n\n') + '\n' : ''}
QUESTION: ${question}`;

  const response = await deepseek.chat.completions.create({
    model: 'deepseek-chat',
    messages: [{ role: 'user', content: prompt }]
  });
  return response.choices[0].message.content;
}

// LLMs drift into GitHub-flavored markdown; convert the common cases to
// Slack mrkdwn so answers don't render with literal ** and ## characters.
function toSlackMrkdwn(text) {
  return String(text || '')
    .replace(/^#{1,6}\s+(.+)$/gm, '*$1*')
    .replace(/\*\*(.+?)\*\*/g, '*$1*')
    .replace(/\[([^\]]+)\]\((https?:[^)]+)\)/g, '<$2|$1>')
    .replace(/^\s*\*\s+/gm, '- ')
    .trim();
}

// Wrap an answer in Block Kit: the text split on line boundaries to respect
// the 3000-char section limit, plus a footer with live context.
function answerBlocks(answer) {
  const text = toSlackMrkdwn(answer);
  const chunks = [];
  let current = '';
  for (const line of text.split('\n')) {
    if (current.length + line.length + 1 > 2900) { chunks.push(current); current = line; }
    else current = current ? `${current}\n${line}` : line;
  }
  if (current) chunks.push(current);

  const blocks = chunks.slice(0, 8).map(c => ({
    type: 'section',
    text: { type: 'mrkdwn', text: c }
  }));

  const active = Object.values(activeIncidents).filter(i => i.status === 'open' || i.status === 'ack').length;
  blocks.push({
    type: 'context',
    elements: [{
      type: 'mrkdwn',
      text: `Live SOC data · ${active} active incident${active === 1 ? '' : 's'} · <${dashboardUrl()}|Open dashboard>`
    }]
  });
  return blocks;
}

// AI assistant panel (requires the Agents & AI Apps toggle in the app config)
const assistant = new Assistant({
  threadStarted: async ({ say, setSuggestedPrompts }) => {
    await say('SOC agent here. Ask me about open incidents, a specific IP, or the current threat picture.');
    await setSuggestedPrompts({
      prompts: [
        { title: 'Open incidents', message: 'What incidents are currently open and which needs attention first?' },
        { title: 'Highest risk', message: 'Which incident has the highest risk score, and what is driving it?' },
        { title: 'Campaign check', message: 'Are any source IPs behind multiple incidents? Summarize the attack chains.' }
      ]
    });
  },
  userMessage: async ({ message, say, setStatus, setTitle }) => {
    const question = (message.text || '').trim();
    if (!question) return;
    try {
      await setStatus('is investigating...');
      await setTitle(question.length > 50 ? `${question.slice(0, 47)}...` : question);
      const answer = await answerAnalystQuestion(question);
      await say({ text: toSlackMrkdwn(answer), blocks: answerBlocks(answer) });
    } catch (err) {
      console.error('Assistant error:', err.message);
      await say(`Sorry, I hit an error answering that: ${err.message}`);
    }
  }
});
app.assistant(assistant);

// In-channel questions: @mention the bot
app.event('app_mention', async ({ event, client }) => {
  const question = (event.text || '').replace(/<@[^>]+>/g, '').trim();
  const threadTs = event.thread_ts || event.ts;
  if (!question) {
    await client.chat.postMessage({
      channel: event.channel,
      thread_ts: threadTs,
      text: 'Ask me something — e.g. "what do we know about 185.220.101.47?" or "summarize open incidents".'
    });
    return;
  }
  try {
    const answer = await answerAnalystQuestion(question);
    await client.chat.postMessage({
      channel: event.channel,
      thread_ts: threadTs,
      text: toSlackMrkdwn(answer),
      blocks: answerBlocks(answer)
    });
  } catch (err) {
    console.error('Mention Q&A error:', err.message);
    await client.chat.postMessage({
      channel: event.channel,
      thread_ts: threadTs,
      text: `Could not answer that: ${err.message}`
    });
  }
});

// Web dashboard: live view of session incidents served by Express.

function computeStats(incidents) {
  const bySeverity = { P1: 0, P2: 0, P3: 0, P4: 0 };
  const byStatus = { open: 0, ack: 0, closed: 0, fp: 0 };
  const categories = {};

  for (const i of incidents) {
    if (bySeverity[i.triage.severity] !== undefined) bySeverity[i.triage.severity]++;
    if (byStatus[i.status] !== undefined) byStatus[i.status]++;
    categories[i.triage.category] = (categories[i.triage.category] || 0) + 1;
  }

  const total = incidents.length;
  const topCategory = Object.entries(categories).sort((a, b) => b[1] - a[1])[0];

  return {
    total,
    bySeverity,
    byStatus,
    fpRate: total ? Math.round((byStatus.fp / total) * 100) : 0,
    resolutionRate: total ? Math.round(((byStatus.closed + byStatus.fp) / total) * 100) : 0,
    correlated: incidents.filter(i => i.correlationData && i.correlationData.count > 0).length,
    topCategory: topCategory ? { name: topCategory[0], count: topCategory[1] } : null
  };
}

// Blast radius: every asset touched by this source IP (this incident +
// correlated ones) and the teams pulled into the response.
function computeBlastRadius(i) {
  const assets = new Set([i.scenario.target]);
  if (i.correlationData) {
    for (const c of i.correlationData.incidents) {
      if (c.target) assets.add(c.target);
    }
  }
  const teams = new Set();
  if (i.triage.escalateTo && i.triage.escalateTo !== 'Unknown') teams.add(i.triage.escalateTo);
  if (i.runbookData && i.runbookData.owner_team) teams.add(i.runbookData.owner_team);
  return {
    assets: [...assets],
    teams: [...teams],
    campaign: !!(i.correlationData && i.correlationData.count > 0)
  };
}

function serializeIncidents() {
  return Object.entries(activeIncidents)
    .map(([ts, i]) => ({
      id: i.incidentId,
      ts,
      severity: i.triage.severity,
      category: i.triage.category,
      confidence: i.triage.confidence,
      type: i.scenario.type,
      sourceIp: i.scenario.source_ip,
      target: i.scenario.target,
      detail: i.scenario.detail,
      summary: i.triage.summary,
      route: i.triage.route,
      routeReason: i.triage.routeReason,
      escalateTo: i.triage.escalateTo,
      falsePositive: i.triage.falsePositive,
      immediateAction: i.triage.immediateAction,
      shortTermAction: i.triage.shortTermAction,
      longTermAction: i.triage.longTermAction,
      status: i.status,
      timestamp: i.timestamp,
      riskScore: i.triage.riskScore != null ? i.triage.riskScore : null,
      riskFactors: i.triage.riskFactors || [],
      abuseScore: i.abuseData ? i.abuseData.abuseScore : null,
      totalReports: i.abuseData ? i.abuseData.totalReports : null,
      isp: i.abuseData ? i.abuseData.isp : null,
      isTor: i.abuseData ? !!i.abuseData.isTor : false,
      vtMalicious: i.vtData ? i.vtData.malicious : null,
      vtTotal: i.vtData ? i.vtData.total : null,
      country: i.vtData ? i.vtData.country : null,
      owner: i.vtData ? i.vtData.owner : null,
      correlatedCount: i.correlationData ? i.correlationData.count : 0,
      correlated: i.correlationData
        ? i.correlationData.incidents.map(c => ({
            id: c.id, type: c.type, target: c.target, severity: c.severity,
            timestamp: c.timestamp, status: c.status, source: c.source
          }))
        : [],
      runbook: i.runbookData
        ? {
            category: i.runbookData.category,
            team: i.runbookData.owner_team,
            sla: i.runbookData.sla_minutes,
            steps: String(i.runbookData.playbook || '').split('\n').filter(Boolean)
          }
        : null,
      events: i.events || [{ at: i.timestamp, type: 'created' }],
      blastRadius: computeBlastRadius(i)
    }))
    .sort((a, b) => Number(b.ts) - Number(a.ts));
}

receiver.app.get('/api/stats', requireDashboardToken, (req, res) => {
  res.json(computeStats(Object.values(activeIncidents)));
});

receiver.app.get('/api/incidents', requireDashboardToken, (req, res) => {
  res.json(serializeIncidents());
});

receiver.app.get('/api/ask', requireDashboardToken, async (req, res) => {
  const question = (req.query.q || '').toString().trim();
  if (!question) return res.status(400).json({ error: 'Missing q parameter' });
  try {
    const answer = await answerAnalystQuestion(question);
    res.json({ question, answer: toSlackMrkdwn(answer), blocks: answerBlocks(answer) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

receiver.app.get('/', (req, res) => {
  const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  res.redirect('/dashboard' + query);
});

receiver.app.get('/dashboard', requireDashboardToken, (req, res) => {
  res.type('html').send(DASHBOARD_HTML);
});

const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>SOC Agent · Live Console</title>
<style>
  :root {
    --bg: #0a0e17; --panel: #121826; --panel2: #0e1420; --border: #1f2937;
    --txt: #e5e9f0; --muted: #7d8aa0; --accent: #38bdf8;
    --p1: #ef4444; --p2: #f59e0b; --p3: #eab308; --p4: #22c55e; --gray: #64748b;
    --mono: 'SFMono-Regular', ui-monospace, 'Cascadia Code', Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--txt); font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; -webkit-font-smoothing: antialiased; }
  a { color: inherit; text-decoration: none; }
  .wrap { max-width: 1240px; margin: 0 auto; padding: 24px; }

  header { display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; margin-bottom: 22px; }
  .brand { display: flex; align-items: center; gap: 12px; }
  .logo { width: 40px; height: 40px; border-radius: 10px; background: linear-gradient(135deg,#38bdf8,#6366f1); display: grid; place-items: center; font-size: 12px; font-weight: 700; letter-spacing: .5px; color: #0a0e17; box-shadow: 0 0 24px rgba(56,189,248,.35); }
  .brand h1 { font-size: 18px; letter-spacing: .3px; }
  .brand p { font-size: 12px; color: var(--muted); font-family: var(--mono); }
  .live { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--muted); font-family: var(--mono); }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--p4); box-shadow: 0 0 10px var(--p4); animation: pulse 1.6s infinite; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .35; } }

  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 22px; }
  .kpi { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px; position: relative; overflow: hidden; }
  .kpi::before { content:''; position:absolute; left:0; top:0; bottom:0; width:3px; background: var(--accent); }
  .kpi.p1::before { background: var(--p1);} .kpi.p2::before { background: var(--p2);} .kpi.p3::before { background: var(--p3);} .kpi.p4::before { background: var(--p4);}
  .kpi .val { font-size: 30px; font-weight: 700; font-family: var(--mono); line-height: 1; }
  .kpi .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; margin-top: 8px; }
  .kpi .sub { font-size: 11px; color: var(--muted); margin-top: 4px; }

  .section-title { font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin: 8px 0 14px; font-family: var(--mono); }

  .cards { display: grid; gap: 12px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 0; overflow: hidden; display: flex; }
  .bar { width: 4px; flex: 0 0 4px; }
  .card-body { padding: 16px 18px; flex: 1; min-width: 0; }
  .card-top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 8px; }
  .id { font-family: var(--mono); font-size: 13px; color: var(--muted); }
  .title { font-weight: 600; font-size: 15px; }
  .pill { font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 999px; font-family: var(--mono); letter-spacing: .4px; }
  .pill.sev { color: #0a0e17; }
  .badge { font-size: 11px; padding: 3px 9px; border-radius: 999px; border: 1px solid var(--border); color: var(--muted); font-family: var(--mono); }
  .badge.corr { color: var(--accent); border-color: rgba(56,189,248,.4); }
  .summary { font-size: 13px; color: #c3ccdc; line-height: 1.5; margin: 6px 0 12px; }
  .meta { display: flex; flex-wrap: wrap; gap: 6px 18px; font-size: 12px; color: var(--muted); font-family: var(--mono); }
  .meta b { color: var(--txt); font-weight: 500; }
  .ml { margin-left: auto; }
  .empty { text-align: center; color: var(--muted); padding: 60px 20px; border: 1px dashed var(--border); border-radius: 12px; font-family: var(--mono); }
  footer { text-align:center; color: var(--muted); font-size: 11px; margin-top: 28px; font-family: var(--mono); }

  /* Expandable incident detail */
  .card { cursor: pointer; transition: border-color .15s; }
  .card:hover { border-color: #31415e; }
  .card:not(.open) .summary { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
  .chev { color: var(--muted); font-size: 11px; font-family: var(--mono); }
  .detail { border-top: 1px solid var(--border); margin-top: 14px; padding-top: 14px; display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  @media (max-width: 820px) { .detail { grid-template-columns: 1fr; } }
  .dsec { background: var(--panel2); border: 1px solid var(--border); border-radius: 10px; padding: 12px 14px; min-width: 0; }
  .dsec.wide { grid-column: 1 / -1; }
  .dtitle { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .8px; font-family: var(--mono); margin-bottom: 8px; }
  .dsec p { font-size: 12.5px; color: #c3ccdc; line-height: 1.55; margin-bottom: 6px; }
  .dsec p:last-child { margin-bottom: 0; }
  .dim { color: var(--muted) !important; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; }
  .chip { font-family: var(--mono); font-size: 11px; padding: 3px 9px; border-radius: 6px; background: rgba(56,189,248,.08); border: 1px solid rgba(56,189,248,.3); color: #9ad8f5; }
  .chip.team { background: rgba(99,102,241,.1); border-color: rgba(99,102,241,.35); color: #b4b8f8; }
  .chip.warn { background: rgba(239,68,68,.1); border-color: rgba(239,68,68,.4); color: #f2a3a3; }
  .tl { list-style: none; margin-left: 5px; }
  .tl li { position: relative; padding: 0 0 12px 18px; border-left: 1px solid var(--border); font-size: 12.5px; color: #c3ccdc; line-height: 1.45; }
  .tl li:last-child { padding-bottom: 0; border-left-color: transparent; }
  .tl li::before { content: ''; position: absolute; left: -4.5px; top: 4px; width: 8px; height: 8px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 6px rgba(56,189,248,.5); }
  .tl li.prior::before { background: var(--gray); box-shadow: none; }
  .tl .when { display: block; color: var(--muted); font-family: var(--mono); font-size: 10.5px; margin-top: 1px; }
  .steps { list-style: none; }
  .steps li { font-size: 12.5px; color: #c3ccdc; line-height: 1.6; padding-left: 4px; }

  /* View tabs + campaign grouping */
  .tabs { display: flex; gap: 8px; margin: 8px 0 14px; }
  .tab { background: var(--panel); border: 1px solid var(--border); color: var(--muted); font-family: var(--mono); font-size: 12px; padding: 7px 14px; border-radius: 8px; cursor: pointer; }
  .tab.active { color: var(--txt); border-color: var(--accent); background: rgba(56,189,248,.08); }
  .campaign { border: 1px solid rgba(56,189,248,.3); background: rgba(56,189,248,.03); border-radius: 14px; padding: 14px; display: grid; gap: 10px; }
  .camp-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .camp-head .ip { font-family: var(--mono); font-size: 15px; font-weight: 700; color: #9ad8f5; }
  .camp-head .arrow { color: var(--muted); font-size: 12px; font-family: var(--mono); }
  .camp-sub { font-size: 12px; color: var(--muted); font-family: var(--mono); }
  .iso-title { font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin: 18px 0 12px; font-family: var(--mono); }
</style>
</head>
<body>
  <div class="wrap">
    <header>
      <div class="brand">
        <div class="logo">SOC</div>
        <div>
          <h1>SOC Agent · Live Console</h1>
          <p>Agentic triage &amp; investigation</p>
        </div>
      </div>
      <div class="live"><span class="dot"></span> LIVE · auto-refresh 5s · <span id="clock"></span></div>
    </header>

    <div class="grid" id="kpis"></div>

    <div class="tabs">
      <button class="tab active" data-view="feed" id="tab-feed">Incident Feed</button>
      <button class="tab" data-view="campaigns" id="tab-campaigns">Campaigns</button>
    </div>
    <div class="cards" id="feed"></div>

    <footer>SOC Agent — session-scoped in-memory feed. Incidents reset on restart.</footer>
  </div>

<script>
  const SEV = {
    P1: { c: 'var(--p1)', l: 'CRITICAL' }, P2: { c: 'var(--p2)', l: 'HIGH' },
    P3: { c: 'var(--p3)', l: 'MEDIUM' }, P4: { c: 'var(--p4)', l: 'LOW' },
    def: { c: 'var(--gray)', l: 'UNKNOWN' }
  };
  const STATUS = {
    open: 'Open', ack: 'Acknowledged', closed: 'Closed', fp: 'False positive'
  };
  const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

  function kpi(val, lbl, cls, sub) {
    return '<div class="kpi ' + (cls||'') + '"><div class="val">' + val + '</div><div class="lbl">' + lbl + '</div>' + (sub ? '<div class="sub">' + sub + '</div>' : '') + '</div>';
  }

  function renderStats(s) {
    const el = document.getElementById('kpis');
    el.innerHTML = [
      kpi(s.total, 'Total Incidents', '', s.correlated + ' correlated'),
      kpi(s.bySeverity.P1, 'P1 Critical', 'p1'),
      kpi(s.bySeverity.P2, 'P2 High', 'p2'),
      kpi(s.bySeverity.P3, 'P3 Medium', 'p3'),
      kpi(s.bySeverity.P4, 'P4 Low', 'p4'),
      kpi(s.byStatus.open, 'Open', '', s.byStatus.ack + ' acknowledged'),
      kpi(s.resolutionRate + '%', 'Resolved', '', s.byStatus.closed + ' closed'),
      kpi(s.fpRate + '%', 'False Positive', '', (s.topCategory ? 'Top: ' + esc(s.topCategory.name) : ''))
    ].join('');
  }

  const EVENT_LABEL = {
    created: 'Incident created — alert fired, AI triage completed',
    ack: 'Acknowledged — analyst began investigating',
    closed: 'Closed — incident resolved',
    fp: 'Dismissed as false positive'
  };
  const expanded = new Set();
  let lastItems = [];

  function timelineHTML(i) {
    const rows = [];
    // Prior correlated activity from the same source IP, oldest first
    (i.correlated || []).forEach(c => {
      rows.push('<li class="prior">Prior: #' + esc(c.id) + ' ' + esc(c.type || 'Unknown') +
        (c.target ? ' → ' + esc(c.target) : '') + (c.severity ? ' (' + esc(c.severity) + ')' : '') +
        '<span class="when">' + esc(c.timestamp || 'earlier') + ' · ' + (c.source === 'rts_search' ? 'found via Slack history' : 'this session') + '</span></li>');
    });
    (i.events || []).forEach(e => {
      let lbl = e.type === 'escalated'
        ? 'Escalated ' + esc(String(e.from || '').toUpperCase()) + ' → ' + esc(String(e.to || '').toUpperCase()) + ' by analyst'
        : (EVENT_LABEL[e.type] || esc(e.type));
      if (e.type === 'escalated' && e.sevFrom && e.sevTo && e.sevFrom !== e.sevTo) {
        lbl += ' · severity ' + esc(e.sevFrom) + ' → ' + esc(e.sevTo);
      }
      rows.push('<li>' + lbl +
        '<span class="when">' + esc(e.at) + (e.by ? ' · by ' + esc(e.by) : '') + '</span></li>');
    });
    return '<ul class="tl">' + rows.join('') + '</ul>';
  }

  function detailHTML(i) {
    const br = i.blastRadius || { assets: [i.target], teams: [], campaign: false };

    const narrative =
      '<div class="dsec wide"><div class="dtitle">Attack Narrative</div>' +
        '<p>' + esc(i.detail) + '</p>' +
        (br.campaign ? '<p>This is not an isolated event — the same source IP appears in ' + i.correlatedCount + ' prior incident(s), suggesting a multi-stage campaign.</p>' : '') +
        '<p class="dim"><b>Routing (' + esc((i.route||'general').toUpperCase()) + '):</b> ' + esc(i.routeReason) + '</p>' +
        '<p class="dim"><b>False-positive assessment:</b> ' + esc(i.falsePositive) + '</p>' +
      '</div>';

    const blast =
      '<div class="dsec"><div class="dtitle">Blast Radius</div>' +
        '<p class="dim">Assets touched by ' + esc(i.sourceIp) + '</p>' +
        '<div class="chips">' +
          br.assets.map(a => '<span class="chip">' + esc(a) + '</span>').join('') +
          (br.campaign ? '<span class="chip warn">multi-stage campaign</span>' : '') +
        '</div>' +
        (br.teams.length ? '<p class="dim" style="margin-top:10px">Teams engaged</p><div class="chips">' + br.teams.map(t => '<span class="chip team">' + esc(t) + '</span>').join('') + '</div>' : '') +
        '<p class="dim" style="margin-top:10px">Origin: ' + esc(i.country || 'Unknown') + (i.isp ? ' · ' + esc(i.isp) : '') + (i.isTor ? ' · Tor exit node' : '') + '</p>' +
      '</div>';

    const timeline =
      '<div class="dsec"><div class="dtitle">Timeline</div>' + timelineHTML(i) + '</div>';

    const playbook =
      '<div class="dsec"><div class="dtitle">Response Playbook</div>' +
        '<p><b>Now (5 min):</b> ' + esc(i.immediateAction) + '</p>' +
        '<p><b>Soon (1 hr):</b> ' + esc(i.shortTermAction) + '</p>' +
        '<p><b>Prevent:</b> ' + esc(i.longTermAction) + '</p>' +
      '</div>';

    const intel =
      '<div class="dsec"><div class="dtitle">Threat Intel</div>' +
        '<p><b>VirusTotal:</b> ' + (i.vtMalicious != null ? esc(i.vtMalicious) + '/' + esc(i.vtTotal) + ' engines flagged · ' + esc(i.owner || 'Unknown owner') : 'unavailable') + '</p>' +
        '<p><b>AbuseIPDB:</b> ' + (i.abuseScore != null ? esc(i.abuseScore) + '% confidence · ' + esc(i.totalReports) + ' reports' : 'unavailable') + '</p>' +
        '<p class="dim"><b>Analyst confidence:</b> ' + esc(i.confidence) + ' · <b>Escalate to:</b> ' + esc(i.escalateTo) + '</p>' +
      '</div>';

    const riskDetail = (i.riskScore != null)
      ? '<div class="dsec"><div class="dtitle">Risk Score — ' + esc(i.riskScore) + '/100</div>' +
          '<ul class="steps">' + (i.riskFactors || []).map(f => '<li>' + esc(f.label) + ' <b>+' + esc(f.points) + '</b></li>').join('') + '</ul>' +
        '</div>'
      : '';

    const runbook = i.runbook
      ? '<div class="dsec"><div class="dtitle">Runbook — ' + esc(i.runbook.category) + ' · ' + esc(i.runbook.team) + ' · SLA ' + esc(i.runbook.sla) + 'm</div>' +
          '<ul class="steps">' + i.runbook.steps.map(s => '<li>' + esc(s) + '</li>').join('') + '</ul></div>'
      : '';

    return '<div class="detail">' + narrative + blast + timeline + playbook + intel + riskDetail + runbook + '</div>';
  }

  function cardHTML(i) {
    const sev = SEV[i.severity] || SEV.def;
    const isOpen = expanded.has(String(i.ts));
    const corr = i.correlatedCount > 0 ? '<span class="badge corr">' + i.correlatedCount + ' linked</span>' : '';
    const vt = (i.vtMalicious != null) ? '<span>VT <b>' + i.vtMalicious + '/' + i.vtTotal + '</b></span>' : '';
    const abuse = (i.abuseScore != null) ? '<span>Abuse <b>' + i.abuseScore + '%</b></span>' : '';
    const riskMeta = (i.riskScore != null) ? '<span>RISK <b>' + i.riskScore + '/100</b></span>' : '';
    return '<div class="card' + (isOpen ? ' open' : '') + '" data-ts="' + esc(i.ts) + '">' +
      '<div class="bar" style="background:' + sev.c + '"></div>' +
      '<div class="card-body">' +
        '<div class="card-top">' +
          '<span class="id">#' + esc(i.id) + '</span>' +
          '<span class="pill sev" style="background:' + sev.c + '">' + esc(i.severity) + ' ' + sev.l + '</span>' +
          '<span class="title">' + esc(i.type) + '</span>' +
          corr +
          '<span class="badge ml">' + (STATUS[i.status] || i.status) + '</span>' +
          '<span class="chev">' + (isOpen ? 'collapse' : 'expand') + '</span>' +
        '</div>' +
        '<div class="summary">' + esc(i.summary) + '</div>' +
        '<div class="meta">' +
          '<span>SRC <b>' + esc(i.sourceIp) + '</b></span>' +
          '<span>DST <b>' + esc(i.target) + '</b></span>' +
          (i.country ? '<span>GEO <b>' + esc(i.country) + '</b></span>' : '') +
          vt + abuse + riskMeta +
          '<span>ROUTE <b>' + esc((i.route||'general').toUpperCase()) + '</b></span>' +
          '<span class="ml">' + esc(i.timestamp) + '</span>' +
        '</div>' +
        (isOpen ? detailHTML(i) : '') +
      '</div>' +
    '</div>';
  }

  const SEV_RANK = { P1: 1, P2: 2, P3: 3, P4: 4 };

  function campaignHTML(ip, group) {
    // Oldest first — a campaign reads chronologically as an attack story
    const chain = group.slice().sort((a, b) => Number(a.ts) - Number(b.ts));
    const worst = chain.reduce((w, i) => (SEV_RANK[i.severity] || 9) < (SEV_RANK[w.severity] || 9) ? i : w, chain[0]);
    const sev = SEV[worst.severity] || SEV.def;
    const assets = [...new Set(chain.map(i => i.target))];
    const openCount = chain.filter(i => i.status === 'open' || i.status === 'ack').length;
    const story = chain.map(i => esc(i.category || i.type)).join(' <span class="arrow">→</span> ');
    return '<div class="campaign">' +
      '<div class="camp-head">' +
        '<span class="ip">' + esc(ip) + '</span>' +
        '<span class="pill sev" style="background:' + sev.c + '">worst: ' + esc(worst.severity) + '</span>' +
        '<span class="badge corr">' + chain.length + ' incidents</span>' +
        (openCount ? '<span class="badge">' + openCount + ' still active</span>' : '<span class="badge">all resolved</span>') +
      '</div>' +
      '<div class="camp-sub">Attack chain: ' + story + '</div>' +
      '<div class="camp-sub">Blast radius: ' + assets.map(a => '<span class="chip">' + esc(a) + '</span>').join(' ') + '</div>' +
      chain.map(cardHTML).join('') +
    '</div>';
  }

  function renderFeed(items) {
    lastItems = items;
    const el = document.getElementById('feed');
    if (!items.length) { el.innerHTML = '<div class="empty">No incidents yet — fire a Splunk webhook or run <b>/simulate-alert</b> in Slack.</div>'; return; }

    if (view === 'campaigns') {
      const byIp = {};
      items.forEach(i => { (byIp[i.sourceIp] = byIp[i.sourceIp] || []).push(i); });
      const campaigns = Object.entries(byIp).filter(e => e[1].length > 1)
        .sort((a, b) => b[1].length - a[1].length);
      const singles = Object.values(byIp).filter(g => g.length === 1).map(g => g[0]);
      let html = '';
      if (!campaigns.length) {
        html += '<div class="empty">No multi-incident campaigns detected — no source IP has more than one incident.</div>';
      } else {
        html += campaigns.map(e => campaignHTML(e[0], e[1])).join('');
      }
      if (singles.length) {
        html += '<div class="iso-title">Isolated incidents</div>' + singles.map(cardHTML).join('');
      }
      el.innerHTML = html;
      return;
    }

    el.innerHTML = items.map(cardHTML).join('');
  }

  document.getElementById('feed').addEventListener('click', ev => {
    if (window.getSelection && String(window.getSelection())) return; // don't toggle while selecting text
    const card = ev.target.closest('.card');
    if (!card || !card.dataset.ts) return;
    const ts = card.dataset.ts;
    if (expanded.has(ts)) expanded.delete(ts); else expanded.add(ts);
    renderFeed(lastItems);
  });

  let view = 'feed';
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      view = btn.dataset.view;
      document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b === btn));
      renderFeed(lastItems);
    });
  });

  // Forward the dashboard access token (if any) to the API endpoints.
  const TOKEN = new URLSearchParams(location.search).get('token');
  const QS = TOKEN ? '?token=' + encodeURIComponent(TOKEN) : '';

  async function refresh() {
    try {
      const [s, list] = await Promise.all([
        fetch('/api/stats' + QS).then(r => r.json()),
        fetch('/api/incidents' + QS).then(r => r.json())
      ]);
      renderStats(s);
      renderFeed(list);
    } catch (e) { /* keep last good render */ }
    document.getElementById('clock').textContent = new Date().toLocaleTimeString();
  }
  refresh();
  setInterval(refresh, 5000);
</script>
</body>
</html>`;

(async () => {
  loadIncidents();
  const port = process.env.PORT || 3000;
  await app.start(port);
  console.log(`SOC Agent running on port ${port}`);
  console.log('Webhook routes: /webhook/splunk and /webhook/github');
  console.log(`Dashboard: ${dashboardUrl()}`);
  if (!process.env.SPLUNK_WEBHOOK_SECRET) console.warn('SPLUNK_WEBHOOK_SECRET not set — /webhook/splunk accepts unauthenticated requests');
  if (!process.env.GITHUB_WEBHOOK_SECRET) console.warn('GITHUB_WEBHOOK_SECRET not set — /webhook/github accepts unauthenticated requests');
  if (!process.env.DASHBOARD_TOKEN) console.warn('DASHBOARD_TOKEN not set — dashboard and API are publicly readable');
})();