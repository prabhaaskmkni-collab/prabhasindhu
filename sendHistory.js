/**
 * sendHistory.js — Persistent Send Log Manager
 * Stores email send logs with timestamps and failure reasons for Daily/Weekly/Monthly/Yearly reporting.
 */

const fs = require('fs');
const path = require('path');

const logFilePath = path.join(__dirname, 'logs/send_history.json');
fs.mkdirSync(path.dirname(logFilePath), { recursive: true });

function readHistory() {
  try {
    if (!fs.existsSync(logFilePath)) return [];
    const data = fs.readFileSync(logFilePath, 'utf8');
    return JSON.parse(data || '[]');
  } catch (err) {
    console.error('Error reading send_history.json:', err.message);
    return [];
  }
}

function writeHistory(records) {
  try {
    fs.writeFileSync(logFilePath, JSON.stringify(records, null, 2), 'utf8');
  } catch (err) {
    console.error('Error writing send_history.json:', err.message);
  }
}

/**
 * Record a list of email results from a campaign run
 */
function recordBatchResults(results = []) {
  if (!Array.isArray(results) || results.length === 0) return;
  const history = readHistory();
  const now = new Date().toISOString();

  const formattedEntries = results.map(r => ({
    id: Math.random().toString(36).substring(2, 10),
    email: r.email || '',
    status: r.status === 'sent' ? 'sent' : 'failed',
    reason: r.reason || r.error || (r.status === 'sent' ? 'Delivered successfully' : 'Unknown delivery failure'),
    smtpHost: r.smtpHost || 'Hostinger SMTP',
    timestamp: r.timestamp || now
  }));

  // Keep last 50,000 logs max
  const updated = [...formattedEntries, ...history].slice(0, 50000);
  writeHistory(updated);
}

/**
 * Get filtered analytics for a given time period
 * @param {'daily' | 'weekly' | 'monthly' | 'yearly'} period 
 */
function getAnalytics(period = 'daily') {
  const history = readHistory();
  const now = new Date();

  let cutoff = new Date();
  if (period === 'daily') {
    cutoff.setHours(now.getHours() - 24);
  } else if (period === 'weekly') {
    cutoff.setDate(now.getDate() - 7);
  } else if (period === 'monthly') {
    cutoff.setDate(now.getDate() - 30);
  } else if (period === 'yearly') {
    cutoff.setFullYear(now.getFullYear() - 1);
  } else {
    cutoff = new Date(0); // all time
  }

  const filtered = history.filter(item => {
    const itemDate = new Date(item.timestamp);
    return itemDate >= cutoff;
  });

  const total = filtered.length;
  const sent = filtered.filter(i => i.status === 'sent').length;
  const failed = filtered.filter(i => i.status === 'failed').length;
  const successRate = total > 0 ? Math.round((sent / total) * 100) : 100;

  // Group failure reasons
  const reasonCounts = {};
  filtered.filter(i => i.status === 'failed').forEach(i => {
    let category = 'Other Failure';
    const r = (i.reason || '').toLowerCase();
    if (r.includes('mx') || r.includes('domain') || r.includes('dns')) category = 'MX Record / Domain Invalid';
    else if (r.includes('auth') || r.includes('login') || r.includes('password') || r.includes('535')) category = 'SMTP Auth Failed';
    else if (r.includes('timeout') || r.includes('connect') || r.includes('refused')) category = 'SMTP Timeout / Connection';
    else if (r.includes('quota') || r.includes('limit') || r.includes('rate')) category = 'Rate Limit / Quota Exceeded';
    else if (r.includes('disposable') || r.includes('spam')) category = 'Disposable / Spam Blocked';
    else category = i.reason || 'General Delivery Error';

    reasonCounts[category] = (reasonCounts[category] || 0) + 1;
  });

  // Build trend data points for chart
  const timeGroupMap = {};
  filtered.forEach(item => {
    const d = new Date(item.timestamp);
    let key;
    if (period === 'daily') {
      key = `${String(d.getHours()).padStart(2, '0')}:00`;
    } else if (period === 'weekly' || period === 'monthly') {
      key = `${d.getMonth() + 1}/${d.getDate()}`;
    } else {
      key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
    }

    if (!timeGroupMap[key]) timeGroupMap[key] = { sent: 0, failed: 0 };
    if (item.status === 'sent') timeGroupMap[key].sent++;
    else timeGroupMap[key].failed++;
  });

  const trendLabels = Object.keys(timeGroupMap).reverse();
  const trendSent = trendLabels.map(k => timeGroupMap[k].sent);
  const trendFailed = trendLabels.map(k => timeGroupMap[k].failed);

  return {
    period,
    summary: {
      total,
      sent,
      failed,
      successRate,
      topFailureReason: Object.keys(reasonCounts)[0] || 'None'
    },
    reasonBreakdown: reasonCounts,
    trends: {
      labels: trendLabels.length > 0 ? trendLabels : ['No Data'],
      sent: trendSent.length > 0 ? trendSent : [0],
      failed: trendFailed.length > 0 ? trendFailed : [0]
    },
    logs: filtered.slice(0, 500) // return top 500 entries for table view
  };
}

module.exports = {
  recordBatchResults,
  getAnalytics,
  readHistory
};
