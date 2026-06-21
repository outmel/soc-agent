if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}
const { App, ExpressReceiver } = require('@slack/bolt');
const OpenAI = require('openai');
const axios = require('axios');
const express = require('express');

const receiver = new ExpressReceiver({
  signingSecret: process.env.SLACK_SIGNING_SECRET
});

receiver.app.use(express.json());
receiver.app.use(express.urlencoded({ extended: true }));

const app = new App({
  token: process.env.SLACK_BOT_TOKEN,
  receiver
});

const deepseek = new OpenAI({
  baseURL: 'https://api.deepseek.com',
  apiKey: process.env.DEEPSEEK_API_KEY,
});

const activeIncidents = {};



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

function getChannelForSeverity(severity) {
  const normalized = (severity || '').trim().toUpperCase();
  const map = {
    P1: process.env.SLACK_CHANNEL_P1,
    P2: process.env.SLACK_CHANNEL_P2,
    P3: process.env.SLACK_CHANNEL_P3,
    P4: process.env.SLACK_CHANNEL_GENERAL
  };
  const channel = map[normalized] || process.env.SLACK_CHANNEL_ID;
  
  if (!channel) {
    console.error(`No channel found for severity "${severity}" — check Railway env vars!`);
  }
  
  return channel;
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
  const related = Object.values(activeIncidents).filter(incident =>
    incident.scenario.source_ip === sourceIp &&
    incident.incidentId !== currentIncidentId
  );

  if (related.length === 0) return null;

  related.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  return {
    count: related.length,
    incidents: related.map(i => ({
      id: i.incidentId,
      type: i.scenario.type,
      severity: i.triage.severity,
      target: i.scenario.target,
      timestamp: i.timestamp,
      status: i.status
    }))
  };
}

async function triageAlert(alert, vtData, abuseData, correlationData) {
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

Based on ALL of this context respond in EXACTLY this format:
SEVERITY: [P1/P2/P3/P4]
CATEGORY: [Brute Force/Malware/Data Exfiltration/Reconnaissance/Other]
CONFIDENCE: [High/Medium/Low]
SUMMARY: [2-3 sentences explaining exactly what is happening and why it matters]
IMMEDIATE_ACTION: [Specific step to take in the next 5 minutes]
SHORT_TERM_ACTION: [What to do in the next hour]
LONG_TERM_ACTION: [What to fix to prevent recurrence]
FALSE_POSITIVE_CHANCE: [percentage with brief reasoning]
ESCALATE_TO: [which team should be notified]`;

  const response = await deepseek.chat.completions.create({
    model: 'deepseek-chat',
    messages: [{ role: 'user', content: prompt }],
  });
  return response.choices[0].message.content;
}

function parseTriageResult(raw) {
  const get = (key) => {
    const match = raw.match(new RegExp(`${key}:\\s*(.+)`));
    return match ? match[1].trim() : 'Unknown';
  };
  return {
    severity: get('SEVERITY'),
    category: get('CATEGORY'),
    confidence: get('CONFIDENCE'),
    summary: get('SUMMARY'),
    immediateAction: get('IMMEDIATE_ACTION'),
    shortTermAction: get('SHORT_TERM_ACTION'),
    longTermAction: get('LONG_TERM_ACTION'),
    falsePositive: get('FALSE_POSITIVE_CHANCE'),
    escalateTo: get('ESCALATE_TO')
  };
}

function severityEmoji(severity) {
  const map = { P1: '🔴', P2: '🟠', P3: '🟡', P4: '🟢' };
  return map[severity] || '⚪';
}

function buildThreadText(incidentId, triage, scenario, timestamp, status, closedBy, vtData, runbookData, abuseData, correlationData) {
  const emoji = severityEmoji(triage.severity);

  const statusLine = {
    open:   `*Status:* 🟡 OPEN — react with 🔒 to close, 👀 to acknowledge, ❌ for false positive`,
    ack:    `*Status:* 👀 ACKNOWLEDGED — being investigated`,
    closed: `*Status:* 🔒 CLOSED — resolved by <@${closedBy}>`,
    fp:     `*Status:* ❌ FALSE POSITIVE — dismissed by <@${closedBy}>`
  }[status];

  const vtSection = vtData
    ? `\n🌐 *VIRUSTOTAL ENRICHMENT*
- Malicious detections: ${vtData.malicious}/${vtData.total} engines
- Suspicious: ${vtData.suspicious}
- Country: ${vtData.country}
- Owner: ${vtData.owner}
- Reputation score: ${vtData.reputation}
- Threat level: ${vtData.flagged ? '🔴 FLAGGED' : '🟢 CLEAN'}\n`
    : `\n🌐 *VIRUSTOTAL ENRICHMENT*\n• Looking up IP...\n`;

  const abuseSection = abuseData
    ? `\n🛡️ *ABUSEIPDB ENRICHMENT*
- Abuse confidence: ${abuseData.abuseScore}% ${abuseData.abuseScore > 80 ? '🔴 HIGH RISK' : abuseData.abuseScore > 40 ? '🟠 MEDIUM RISK' : '🟢 LOW RISK'}
- Total reports: ${abuseData.totalReports}
- Last reported: ${abuseData.lastReported}
- ISP: ${abuseData.isp}
- Usage type: ${abuseData.usageType}
- Tor exit node: ${abuseData.isTor ? '⚠️ YES' : 'No'}\n`
    : '';

  const correlationSection = correlationData && correlationData.count > 0
    ? `\n🔗 *CORRELATED INCIDENTS DETECTED*
⚠️ This source IP has ${correlationData.count} other related incident(s) — possible multi-stage attack campaign
${correlationData.incidents.map(i => `• #${i.id}: ${i.type} → ${i.target} (${i.severity}) at ${i.timestamp} [${i.status}]`).join('\n')}\n`
    : '';

  const runbookSection = runbookData
    ? `\n📖 *MCP RUNBOOK — ${runbookData.category.toUpperCase()}*
- Owner team: ${runbookData.owner_team}
- SLA: Respond within ${runbookData.sla_minutes} minutes
${runbookData.playbook.split('\n').map(s => `• ${s}`).join('\n')}\n`
    : '';

  return `${emoji} *INCIDENT #${incidentId} — ${triage.severity} ${triage.category.toUpperCase()}*
━━━━━━━━━━━━━━━━━━━━━━━━━━━
*Type:* ${scenario.type}
*Source:* \`${scenario.source_ip}\`
*Target:* \`${scenario.target}\`
*Time:* ${timestamp}
*Detail:* ${scenario.detail}
${vtSection}${abuseSection}${correlationSection}${runbookSection}
🤖 *AI TRIAGE*
- Severity: ${triage.severity} ${emoji}
- Category: ${triage.category}
- Confidence: ${triage.confidence}
- False Positive Chance: ${triage.falsePositive}
- Escalate to: ${triage.escalateTo}

📋 *SUMMARY*
${triage.summary}

⚡ *RESPONSE ACTIONS*
🔴 *Immediate (next 5 min):* ${triage.immediateAction}
🟠 *Short-term (next hour):* ${triage.shortTermAction}
🟢 *Long-term (prevent recurrence):* ${triage.longTermAction}

${statusLine}`;
}

async function processAlert(client, channelId, customAlert = null) {
  const scenario = customAlert || ALERT_SCENARIOS[Math.floor(Math.random() * ALERT_SCENARIOS.length)];
  const incidentId = Math.floor(Math.random() * 9000) + 1000;
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

  const initial = await client.chat.postMessage({
    channel: channelId,
    text: `🚨 *INCOMING ALERT* — AI triage in progress...`,
  });

  try {
    const [vtData, abuseData] = await Promise.all([
      enrichIP(scenario.source_ip),
      enrichIPAbuse(scenario.source_ip)
    ]);

    const correlationData = await findRelatedOffenses(scenario.source_ip, incidentId);

    const rawTriageEnriched = await triageAlert(scenario, vtData, abuseData, correlationData);
    const triage = parseTriageResult(rawTriageEnriched);
    const emoji = severityEmoji(triage.severity);

    const targetChannel = getChannelForSeverity(triage.severity);

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
      text: `${emoji} *INCIDENT #${incidentId}* — ${triage.severity} | ${scenario.type} | Routed to ${triage.severity} channel`
    });

    const severityMsg = await client.chat.postMessage({
      channel: targetChannel,
      text: `${emoji} *INCIDENT #${incidentId}* — ${triage.severity} | ${scenario.type}${correlationData ? ` 🔗 (linked to ${correlationData.count} prior incident${correlationData.count > 1 ? 's' : ''})` : ''} | 🟡 OPEN`
    });

    const threadMsg = await client.chat.postMessage({
      channel: targetChannel,
      thread_ts: severityMsg.ts,
      text: buildThreadText(incidentId, triage, scenario, timestamp, 'open', null, vtData, runbookData, abuseData, correlationData)
    });

    if (triage.severity === 'P1') {
      await client.chat.postMessage({
        channel: targetChannel,
        thread_ts: severityMsg.ts,
        text: `🚨 *P1 CRITICAL* — <!channel> This requires immediate attention. React with 👀 to acknowledge.`
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
      status: 'open'
    };

  } catch (err) {
    console.error('Triage error:', err);
    await client.chat.postMessage({
      channel: channelId,
      thread_ts: initial.ts,
      text: `❌ AI triage failed: ${err.message}`
    });
  }
}

receiver.app.post('/webhook/splunk', async (req, res) => {
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

app.event('reaction_added', async ({ event, client }) => {
  const incident = activeIncidents[event.item.ts];
  if (!incident) return;

  const { reaction } = event;
  const userId = event.user;

  let newStatus = null;
  if (reaction === 'lock' || reaction === '🔒')       newStatus = 'closed';
  else if (reaction === 'eyes' || reaction === '👀')  newStatus = 'ack';
  else if (reaction === 'x' || reaction === '❌')     newStatus = 'fp';

  if (!newStatus) return;
  if (incident.status === newStatus) return;

  incident.status = newStatus;

  const emoji = severityEmoji(incident.triage.severity);
  const statusLabel = {
    closed: '🔒 CLOSED',
    ack:    '👀 ACKNOWLEDGED',
    fp:     '❌ FALSE POSITIVE'
  }[newStatus];

  await client.chat.update({
    channel: incident.channelId,
    ts: incident.parentTs,
    text: `${emoji} *INCIDENT #${incident.incidentId}* — ${incident.triage.severity} | ${incident.scenario.type} | ${statusLabel}`
  });

  await client.chat.update({
    channel: incident.channelId,
    ts: incident.threadTs,
    text: buildThreadText(
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
    )
  });

  const statusMessages = {
    closed: `🔒 Incident closed by <@${userId}>. Marking as resolved.`,
    ack:    `👀 <@${userId}> is on it. Incident acknowledged.`,
    fp:     `❌ Marked as false positive by <@${userId}>. Dismissed.`
  };

  await client.chat.postMessage({
    channel: incident.channelId,
    thread_ts: incident.parentTs,
    text: statusMessages[newStatus]
  });
});

app.command('/soc-stats', async ({ ack, client, body }) => {
  await ack();

  (async () => {
    const incidents = Object.values(activeIncidents);

    if (incidents.length === 0) {
      await client.chat.postMessage({
        channel: body.channel_id,
        text: `📊 *SOC DASHBOARD*\nNo incidents recorded this session yet. Run \`/simulate-alert\` to generate one.`
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
      text: `📊 *SOC DASHBOARD — LIVE SESSION STATS*\n━━━━━━━━━━━━━━━━━━━━━━━━━━━\n*SEVERITY BREAKDOWN*\n🔴 P1 Critical: ${p1}\n🟠 P2 High: ${p2}\n🟡 P3 Medium: ${p3}\n🟢 P4 Low: ${p4}\n📈 Total: ${incidents.length}\n\n*INCIDENT STATUS*\n🟡 Open: ${open}\n👀 Acknowledged: ${acked}\n🔒 Closed: ${closed}\n❌ False Positives: ${fp}\n\n*METRICS*\n- False Positive Rate: ${fpRate}%\n- Top Threat Category: ${topCategory ? topCategory[0] : 'N/A'} (${topCategory ? topCategory[1] : 0} incidents)\n- Resolution Rate: ${Math.round(((closed + fp) / incidents.length) * 100)}%`
    });
  })();
});

app.command('/simulate-alert', async ({ ack, client, body }) => {
  await ack();
  await client.chat.postMessage({
    channel: body.channel_id,
    text: `🔄 Alert simulation started — routing to severity channel after triage...`
  });
  processAlert(client, body.channel_id);
});

(async () => {
  await app.start(3000);
  console.log('⚡ SOC Agent running on port 3000');
  console.log('🔗 Webhook routes: /webhook/splunk and /webhook/github');
})();