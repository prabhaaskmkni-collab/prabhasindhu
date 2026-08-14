/**
 * Express API Server
 * REST endpoints for email validation & bulk sending
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { parse } = require('csv-parse/sync');
const XLSX = require('xlsx');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const { OAuth2Client } = require('google-auth-library');

const { validateEmail, validateEmailBatch } = require('./emailValidator');
const { createTransporter, testSMTPConnection, testSendGridConnection, sendBulkEmails, dailyQuota, getSMTPPresets } = require('./mailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool, initDB, findUserByEmail, createUser, getAllUsers } = require('./db');
const { recordBatchResults, getAnalytics, readHistory } = require('./sendHistory');

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;
const JWT_SECRET = process.env.JWT_SECRET || 'mf-super-secret-jwt-key-2024';

// Initialize PostgreSQL database tables / local store
initDB();

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(__dirname));

// File upload config
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB max for large email lists
});

// In-memory job store
const jobs = new Map();

// ─── Logging ───────────────────────────────────────────────────────────────
const logFile = path.join(__dirname, 'logs/activity.log');
fs.mkdirSync(path.dirname(logFile), { recursive: true });

function log(level, message, data = {}) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...data
  };
  const line = JSON.stringify(entry) + '\n';
  fs.appendFileSync(logFile, line);
  if (process.env.NODE_ENV !== 'production') {
    console.log(`[${level.toUpperCase()}] ${message}`, Object.keys(data).length ? data : '');
  }
}

// ─── API Routes ────────────────────────────────────────────────────────────

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    quota: dailyQuota.stats(),
    timestamp: new Date().toISOString()
  });
});

// App config endpoint (provides GOOGLE_CLIENT_ID and default SMTP config to client UI)
app.get('/api/config', (req, res) => {
  res.json({
    googleClientId: process.env.GOOGLE_CLIENT_ID || '',
    smtpDefaults: {
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: process.env.SMTP_PORT || '587',
      user: process.env.SMTP_USER || '',
      pass: process.env.SMTP_PASS || '',
      secure: process.env.SMTP_SECURE === 'true',
      fromName: process.env.SMTP_FROM_NAME || '',
      fromEmail: process.env.SMTP_FROM_EMAIL || ''
    }
  });
});

// ─── AUTHENTICATION ENDPOINTS ──────────────────

// 1. REGISTER
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, error: 'Name, email, and password are required' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const existing = await findUserByEmail(cleanEmail);

    if (existing) {
      return res.status(400).json({ success: false, error: 'An account with this email already exists. Please sign in.' });
    }

    const password_hash = await bcrypt.hash(password, 10);
    const picture = `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=6366f1&color=fff`;

    const user = await createUser({ name: name.trim(), email: cleanEmail, password_hash, picture });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

    log('info', `User registered: ${user.email}`);
    return res.json({ success: true, token, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2. LOGIN
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password are required' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const user = await findUserByEmail(cleanEmail);

    if (!user) {
      return res.status(401).json({ success: false, error: 'No account found with this email. Please create an account first.' });
    }

    if (!user.password_hash) {
      return res.status(401).json({ success: false, error: 'This account uses Google Sign-In. Please sign in with Google.' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ success: false, error: 'Incorrect password. Please try again.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    const userProfile = { id: user.id, name: user.name, email: user.email, picture: user.picture };

    log('info', `User logged in: ${user.email}`);
    return res.json({ success: true, token, user: userProfile });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 3. GOOGLE SIGN-IN / TOKEN VERIFY
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { credential, userInfo } = req.body;
    let payload = null;

    if (credential && googleClient) {
      try {
        const ticket = await googleClient.verifyIdToken({
          idToken: credential,
          audience: GOOGLE_CLIENT_ID
        });
        payload = ticket.getPayload();
      } catch (e) {
        console.warn('Google token verification failed, using client payload if provided:', e.message);
      }
    }

    if (!payload && userInfo) {
      payload = userInfo;
    }

    if (!payload && credential) {
      try {
        const parts = credential.split('.');
        payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      } catch(e) {}
    }

    if (!payload || (!payload.email && !payload.sub)) {
      return res.status(400).json({ success: false, error: 'Invalid Google authentication credentials' });
    }

    const email = (payload.email || '').toLowerCase().trim();
    const name = payload.name || payload.given_name || email.split('@')[0];
    const picture = payload.picture || `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=6366f1&color=fff`;
    const googleId = payload.sub || payload.id || '';

    let user = await findUserByEmail(email);
    if (!user) {
      user = await createUser({ name, email, password_hash: null, google_id: googleId, picture });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    log('info', `Google user logged in: ${email}`);
    return res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email, picture: user.picture } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 4. ADMIN VIEW USERS IN DB
app.get('/api/admin/users', async (req, res) => {
  try {
    const users = await getAllUsers();
    res.json({
      success: true,
      totalUsers: users.length,
      users
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Database query error: ' + err.message });
  }
});

// ── Validate Single Email ──
app.post('/api/validate/single', async (req, res) => {
  try {
    const { email, checkSmtp = true, checkDisposable = true, checkRoleBased = false } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email address is required' });
    }

    log('info', 'Validating single email', { email: email.substring(0, 50) });

    const result = await validateEmail(email, { checkSmtp, checkDisposable, checkRoleBased });

    log('info', 'Validation complete', {
      email: result.email,
      status: result.status,
      score: result.score
    });

    res.json(result);
  } catch (err) {
    log('error', 'Single validation error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ── Validate Multiple Emails (JSON body) ──
app.post('/api/validate/bulk', async (req, res) => {
  try {
    const { emails, checkSmtp = true, checkDisposable = true } = req.body;

    if (!emails || !Array.isArray(emails)) {
      return res.status(400).json({ error: 'emails array is required' });
    }

    if (emails.length > 50000) {
      return res.status(400).json({ error: 'Max 50000 emails per request.' });
    }

    const jobId = uuidv4();
    const job = {
      id: jobId,
      type: 'validation',
      status: 'running',
      total: emails.length,
      completed: 0,
      results: [],
      startTime: Date.now()
    };
    jobs.set(jobId, job);

    log('info', `Starting bulk validation job ${jobId}`, { count: emails.length });

    // Run async
    (async () => {
      try {
        const results = await validateEmailBatch(
          emails,
          { checkSmtp, checkDisposable, concurrency: checkSmtp ? 50 : 100 },
          (completed, total, result) => {
            job.completed = completed;
            job.results.push(result);
          }
        );

        job.status = 'completed';
        job.endTime = Date.now();
        job.summary = buildValidationSummary(results);

        log('info', `Validation job ${jobId} completed`, { total: results.length });
      } catch (err) {
        job.status = 'failed';
        job.error = err.message;
        log('error', `Validation job ${jobId} failed`, { error: err.message });
      }
    })();

    res.json({ jobId, message: `Validating ${emails.length} emails`, status: 'started' });
  } catch (err) {
    log('error', 'Bulk validation error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ── Upload CSV and Validate ──
app.post('/api/validate/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'File is required' });
    }

    let emails = [];
    const ext = path.extname(req.file.originalname).toLowerCase();

    if (ext === '.xlsx' || ext === '.xls') {
      const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
      const sheetName = workbook.SheetNames[0];
      const sheet = workbook.Sheets[sheetName];
      const rows = XLSX.utils.sheet_to_json(sheet, { defval: '' });

      if (rows.length > 0) {
        const keys = Object.keys(rows[0]);
        const emailCol = findEmailColumn(keys);
        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;

        for (const row of rows) {
          const directVal = String(row[emailCol] || '').trim();
          if (emailRegex.test(directVal)) {
            emails.push(directVal.match(emailRegex)[0]);
            continue;
          }
          for (const key of keys) {
            const val = String(row[key] || '').trim();
            if (emailRegex.test(val)) {
              emails.push(val.match(emailRegex)[0]);
              break;
            }
          }
        }
      }
    } else if (ext === '.csv') {
      try {
        const fileContent = req.file.buffer.toString('utf-8');
        const rows = parse(fileContent, {
          columns: true,
          skip_empty_lines: true,
          trim: true
        });
        const emailCol = findEmailColumn(rows[0] ? Object.keys(rows[0]) : []);
        emails = rows.map(r => r[emailCol] || r[Object.keys(r)[0]]).filter(Boolean);
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        emails = emails.map(e => e.trim().toLowerCase()).filter(e => emailRegex.test(e));
      } catch (csvErr) {
        const fileContent = req.file.buffer.toString('utf-8');
        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        emails = fileContent.match(emailRegex) || [];
      }
    } else {
      const fileContent = req.file.buffer.toString('utf-8');
      const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
      emails = fileContent.match(emailRegex) || [];
    }

    // De-duplicate and clean
    emails = [...new Set(emails.map(e => e.trim().toLowerCase()))];

    if (emails.length === 0) {
      return res.status(400).json({ error: 'No valid email addresses found in file' });
    }

    if (emails.length > 20000) {
      return res.status(400).json({ error: `Too many emails. Max 20000, got ${emails.length}` });
    }

    const jobId = uuidv4();
    const job = {
      id: jobId,
      type: 'validation',
      status: 'running',
      total: emails.length,
      completed: 0,
      results: [],
      startTime: Date.now()
    };
    jobs.set(jobId, job);

    const checkSmtp = req.body.check_smtp === 'true' || req.body.checkSmtp === 'true' || req.body.check_smtp === true || req.body.checkSmtp === true;
    const checkDisposable = req.body.checkDisposable !== 'false';

    log('info', `Starting upload validation job ${jobId}`, { count: emails.length, file: req.file.originalname, checkSmtp });

    (async () => {
      try {
        await validateEmailBatch(
          emails,
          { checkSmtp, checkDisposable, checkRoleBased: true, concurrency: checkSmtp ? 50 : 100, delayMs: 0 },
          (completed, total, result) => {
            job.completed = completed;
            
            // Build format reasons
            let reason = '';
            if (checkSmtp) {
              reason = result.checks.smtp.reason || '';
            }
            if (!reason) reason = result.checks.domain.reason || result.checks.disposable.reason || result.checks.syntax.reason || '';

            job.results.push({
              email: result.email,
              status: result.status,
              score: result.score,
              responseTimeMs: result.responseTimeMs,
              domain: result.email.split('@')[1] || '',
              has_mx: result.checks.domain.passed,
              is_disposable: !result.checks.disposable.passed,
              is_role_based: !result.checks.roleBased.passed,
              reason
            });
          }
        );

        job.status = 'completed';
        job.endTime = Date.now();
        job.summary = buildValidationSummary(job.results);

        log('info', `Upload validation job ${jobId} completed`, { total: job.results.length });
      } catch (err) {
        job.status = 'failed';
        job.error = err.message;
        log('error', `Upload validation job ${jobId} failed`, { error: err.message });
      }
    })();

    res.json({
      jobId,
      message: `Processing ${emails.length} emails from ${req.file.originalname}`,
      status: 'started'
    });
  } catch (err) {
    log('error', 'Upload validation error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ── Get Job Status ──
app.get('/api/jobs/:jobId', (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Job not found' });

  const response = {
    id: job.id,
    type: job.type,
    status: job.status,
    total: job.total,
    completed: job.completed,
    progress: Math.round((job.completed / job.total) * 100),
    elapsedMs: Date.now() - job.startTime,
    ...(job.status === 'completed' && { summary: job.summary, durationMs: job.endTime - job.startTime }),
    ...(job.status === 'failed' && { error: job.error }),
    ...(job.error && { error: job.error })
  };

  // Include results if completed
  if (job.status === 'completed') {
    response.results = job.results;
  }

  res.json(response);
});

// ── Download Job Results as CSV (Validation & Bulk Send) ──
app.get('/api/jobs/:jobId/download', (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (job.status !== 'completed') return res.status(400).json({ error: 'Job not completed yet' });

  const filter = req.query.filter;
  let results = job.results || [];

  if (job.type === 'bulk-send') {
    if (filter) results = results.filter(r => r.status === filter);
    const csv = buildBulkSendCSV(results);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="bulk-send-${filter || 'all'}-${job.id.slice(0, 8)}.csv"`);
    return res.send(csv);
  }

  // Else validation job:
  if (filter) results = results.filter(r => r.status === filter);
  const csv = buildCSV(results);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="validation-${filter || 'all'}-${job.id.slice(0, 8)}.csv"`);
  res.send(csv);
});

// ── SMTP: Get Presets ──
app.get('/api/smtp/presets', (req, res) => {
  res.json(getSMTPPresets());
});

// ── SMTP: Test Connection ──
app.post('/api/smtp/test', async (req, res) => {
  try {
    const { host, port, secure, user, pass, fromName, fromEmail, provider, apiKey, awsAccessKeyId, awsSecretAccessKey, awsRegion } = req.body;

    if (provider === 'sendgrid') {
      const keyToTest = apiKey || process.env.SENDGRID_API_KEY;
      if (!keyToTest || keyToTest === 'YOUR_SENDGRID_API_KEY_HERE') {
        return res.status(400).json({ error: 'SendGrid API key is required' });
      }
      log('info', 'Testing SendGrid connection');
      const result = await testSendGridConnection(keyToTest);
      log(result.success ? 'info' : 'warn', 'SendGrid test result', { success: result.success });
      return res.json(result);
    }

    if (provider === 'ses') {
      const keyId = awsAccessKeyId || process.env.AWS_ACCESS_KEY_ID;
      const secretKey = awsSecretAccessKey || process.env.AWS_SECRET_ACCESS_KEY;
      const region = awsRegion || process.env.AWS_REGION || 'us-east-1';

      if (!keyId || keyId === 'YOUR_AWS_ACCESS_KEY_ID_HERE') {
        return res.status(400).json({ error: 'AWS Access Key ID is required' });
      }
      if (!secretKey || secretKey === 'YOUR_AWS_SECRET_ACCESS_KEY_HERE') {
        return res.status(400).json({ error: 'AWS Secret Access Key is required' });
      }

      log('info', 'Testing AWS SES connection', { region });
      const result = await testSMTPConnection({
        provider: 'ses',
        awsAccessKeyId: keyId,
        awsSecretAccessKey: secretKey,
        awsRegion: region,
        fromName,
        fromEmail
      });
      log(result.success ? 'info' : 'warn', 'AWS SES test result', { success: result.success });
      return res.json(result);
    }

    if (!host || !user || !pass) {
      return res.status(400).json({ error: 'host, user, and pass are required' });
    }

    log('info', 'Testing SMTP connection', { host, port, user: user.substring(0, 20) });

    const result = await testSMTPConnection({ host, port, secure, user, pass, fromName, fromEmail });

    log(result.success ? 'info' : 'warn', 'SMTP test result', { success: result.success, host });

    res.json(result);
  } catch (err) {
    log('error', 'SMTP test error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ── Send Bulk Emails ──
app.post('/api/email/send-bulk', async (req, res) => {
  try {
    const { recipients, template, smtp } = req.body;

    // Determine provider: request body > env > default smtp
    const provider = (smtp?.provider || process.env.SEND_PROVIDER || 'smtp').toLowerCase();
    const useSendGrid = provider === 'sendgrid';

    if (!recipients || !Array.isArray(recipients) || recipients.length === 0) {
      return res.status(400).json({ error: 'recipients array is required' });
    }
    if (!template || !template.subject) {
      return res.status(400).json({ error: 'template with subject is required' });
    }

    // Validate provider credentials
    if (provider === 'smtp') {
      if (!smtp || !smtp.host || !smtp.user || !smtp.pass) {
        return res.status(400).json({ error: 'smtp config with host, user, and pass is required' });
      }
    } else if (provider === 'sendgrid') {
      const apiKey = smtp?.apiKey || process.env.SENDGRID_API_KEY;
      if (!apiKey || apiKey === 'YOUR_SENDGRID_API_KEY_HERE') {
        return res.status(400).json({ error: 'SendGrid API key is not set in .env and no API key was provided. Please add your SendGrid API key.' });
      }
    } else if (provider === 'ses') {
      const accessKeyId = smtp?.awsAccessKeyId || process.env.AWS_ACCESS_KEY_ID;
      const secretAccessKey = smtp?.awsSecretAccessKey || process.env.AWS_SECRET_ACCESS_KEY;
      if (!accessKeyId || accessKeyId === 'YOUR_AWS_ACCESS_KEY_ID_HERE') {
        return res.status(400).json({ error: 'AWS Access Key ID is not set in .env and no Access Key was provided.' });
      }
      if (!secretAccessKey || secretAccessKey === 'YOUR_AWS_SECRET_ACCESS_KEY_HERE') {
        return res.status(400).json({ error: 'AWS Secret Access Key is not set in .env and no Secret Key was provided.' });
      }
    }

    const jobId = uuidv4();
    const job = {
      id: jobId,
      type: 'bulk-send',
      status: 'running',
      total: recipients.length,
      sent: 0,
      failed: 0,
      results: [],
      startTime: Date.now()
    };
    jobs.set(jobId, job);

    log('info', `Starting bulk send job ${jobId}`, { count: recipients.length });

    (async () => {
      try {
        const result = await sendBulkEmails(
          recipients,
          template,
          smtp,
          ({ type, detail }) => {
            if (type === 'sent') job.sent++;
            else if (type === 'failed') job.failed++;
            job.completed = job.sent + job.failed;
            job.results.push(detail);
          }
        );

        job.status = 'completed';
        job.endTime = Date.now();
        job.summary = {
          total: result.total,
          sent: result.sent,
          failed: result.failed,
          durationMs: result.durationMs
        };

        log('info', `Bulk send job ${jobId} completed`, { sent: result.sent, failed: result.failed });
      } catch (err) {
        job.status = 'failed';
        job.error = err.message;
        log('error', `Bulk send job ${jobId} failed`, { error: err.message });
      }
    })();

    res.json({
      jobId,
      message: `Sending ${recipients.length} emails (3 concurrent)`,
      status: 'started',
      quota: dailyQuota.stats()
    });
  } catch (err) {
    log('error', 'Bulk send error', { error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ── Quota Status ──
app.get('/api/quota', (req, res) => {
  res.json(dailyQuota.stats());
});

// ── Get Logs ──
app.get('/api/logs', (req, res) => {
  try {
    if (!fs.existsSync(logFile)) return res.json([]);
    const content = fs.readFileSync(logFile, 'utf-8');
    const lines = content.trim().split('\n').filter(Boolean);
    const logs = lines.slice(-200).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    res.json(logs.reverse());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Catch-all → serve UI ──
// ─── FastAPI Compatible Endpoints ───────────────────────────────────────────

// Helper: strip HTML tags
function stripHtml(html) {
  if (!html) return '';
  return html.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
}

// Helper: prepare email HTML body, CIDs for inline images and attachments
function prepareEmailContent(body, plain_msg, images, attachmentsPayload) {
  let html = body || '';
  
  if (html.trim()) {
    const isFullHtml = html.trim().toLowerCase().startsWith('<!doctype') || html.toLowerCase().includes('<html');
    if (plain_msg && !isFullHtml) {
      const block = `
<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 20px">
  <tr>
    <td align="center">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#f0f4ff;border-left:4px solid #6366f1;border-radius:0 10px 10px 0;padding:20px 24px">
        <tr>
          <td style="color:#374151;font-size:.98rem;line-height:1.8">
            ${plain_msg.replace(/\n/g, '<br>')}
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>`;
      const ins = html.includes('<body') ? html.indexOf('>', html.indexOf('<body')) + 1 : 0;
      html = ins ? (html.slice(0, ins) + block + html.slice(ins)) : (block + html);
    }
  } else {
    html = `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;font-family:Arial,sans-serif;"><!-- SIGNATURE_PLACEHOLDER --></body></html>`;
  }

  const nodemailerAttachments = [];
  let inlineImgIndex = 0;

  // Extract inline base64 images from HTML body
  const b64Regex = /(src=["'])(data:image\/(jpeg|jpg|png|gif|webp);base64,([A-Za-z0-9+/=]+))(["'])/gi;
  html = html.replace(b64Regex, (match, prefix, dataUrl, mimeSubtype, base64Content, suffix) => {
    const cid = `inline_${inlineImgIndex++}_${Math.random().toString(36).substring(2, 10)}@mailforge`;
    nodemailerAttachments.push({
      filename: `inline_${inlineImgIndex}.${mimeSubtype}`,
      content: Buffer.from(base64Content, 'base64'),
      cid: cid
    });
    return `${prefix}cid:${cid}${suffix}`;
  });

  // Process explicitly uploaded images
  let signatureTag = '';
  if (images && Array.isArray(images)) {
    images.forEach((img, idx) => {
      let raw = img.content || '';
      if (!raw || raw === 'undefined' || raw.length < 10) return;
      if (raw.includes(',')) raw = raw.split(',')[1];
      
      const filename = img.filename || `image${idx}.jpg`;
      const ext = filename.split('.').pop().toLowerCase();
      const subtype = ['gif', 'png', 'jpeg', 'webp'].includes(ext) ? ext : 'jpeg';
      const cid = `img_${idx}_${Math.random().toString(36).substring(2, 10)}@mailforge`;

      nodemailerAttachments.push({
        filename: filename,
        content: Buffer.from(raw, 'base64'),
        cid: cid
      });

      const isSig = img.is_default_gif || img.position === 'signature';
      if (isSig) {
        signatureTag = `
<table cellpadding="0" cellspacing="0" border="0" style="margin:16px 0 0 0;">
  <tr>
    <td style="padding:0;">
      <img src="cid:${cid}" alt="Signature" style="display:block;height:auto;max-height:160px;width:auto;max-width:480px;border:none;outline:none;"/>
    </td>
  </tr>
</table>`;
      } else if (img.data_url && html.includes(img.data_url)) {
        html = html.replaceAll(img.data_url, `cid:${cid}`);
      } else {
        const imgTag = `
<table width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0">
  <tr>
    <td align="center" style="padding:0 20px">
      <img src="cid:${cid}" alt="${filename}" style="display:block;height:auto;max-width:560px;width:100%;border-radius:10px;box-shadow:0 4px 16px rgba(0,0,0,.10);"/>
    </td>
  </tr>
</table>`;
        const ins = html.includes('<body') ? html.indexOf('>', html.indexOf('<body')) + 1 : 0;
        html = ins ? (html.slice(0, ins) + imgTag + html.slice(ins)) : (imgTag + html);
      }
    });
  }

  if (signatureTag) {
    if (html.includes('<!-- SIGNATURE_PLACEHOLDER -->')) {
      html = html.replace('<!-- SIGNATURE_PLACEHOLDER -->', signatureTag);
    } else if (html.includes('</body>')) {
      html = html.replace('</body>', signatureTag + '</body>');
    } else {
      html += signatureTag;
    }
  }

  // Process file attachments
  if (attachmentsPayload && Array.isArray(attachmentsPayload)) {
    attachmentsPayload.forEach(att => {
      let raw = att.content || '';
      if (!raw) return;
      if (raw.includes(',')) raw = raw.split(',')[1];
      nodemailerAttachments.push({
        filename: att.filename || 'attachment.bin',
        content: Buffer.from(raw, 'base64')
      });
    });
  }

  return { html, attachments: nodemailerAttachments };
}

// Single Validation
app.post('/api/validate-single', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, error: 'Email is required' });
    }
    const result = await validateEmail(email, { checkSmtp: true, checkDisposable: true, checkRoleBased: true });
    let reason = result.checks.smtp.reason || result.checks.domain.reason || result.checks.disposable.reason || result.checks.syntax.reason || '';
    if (result.status === 'valid') {
      reason = 'Valid — MX records confirmed';
    }

    res.json({
      success: true,
      email: result.email,
      status: result.status,
      reason: reason,
      has_mx: result.checks.domain.passed,
      is_disposable: !result.checks.disposable.passed,
      is_role_based: !result.checks.roleBased.passed
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Bulk Validation (file upload) — main entry point used by the UI
app.post('/api/validate', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'File is required' });
    }

    const email_column = req.body.email_column || 'email';
    const checkSmtp = req.body.check_smtp === 'true' || req.body.checkSmtp === 'true';
    const ext = path.extname(req.file.originalname).toLowerCase();
    let emails = [];

    // ── Parse XLSX / XLS ──
    if (ext === '.xlsx' || ext === '.xls') {
      const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
      const sheetName = workbook.SheetNames[0];
      const sheet = workbook.Sheets[sheetName];
      const rows = XLSX.utils.sheet_to_json(sheet, { defval: '' });
      const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;
      for (const row of rows) {
        for (const val of Object.values(row)) {
          const str = String(val || '').trim();
          const m = str.match(emailRegex);
          if (m) { emails.push(m[0].toLowerCase()); break; }
        }
      }
    }
    // ── Parse CSV ──
    else if (ext === '.csv') {
      try {
        const fileContent = req.file.buffer.toString('utf-8');
        const rows = parse(fileContent, { columns: true, skip_empty_lines: true, trim: true });
        const keys = rows[0] ? Object.keys(rows[0]) : [];
        const emailCol = keys.includes(email_column) ? email_column : findEmailColumn(keys);
        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;
        for (const row of rows) {
          const str = String(row[emailCol] || row[keys[0]] || '').trim();
          const m = str.match(emailRegex);
          if (m) emails.push(m[0].toLowerCase());
        }
      } catch (csvErr) {
        const fileContent = req.file.buffer.toString('utf-8');
        emails = (fileContent.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []).map(e => e.toLowerCase());
      }
    }
    // ── Plain text / TXT ──
    else {
      const fileContent = req.file.buffer.toString('utf-8');
      emails = (fileContent.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []).map(e => e.toLowerCase());
    }

    // De-duplicate
    emails = [...new Set(emails)];

    if (emails.length === 0) {
      return res.status(400).json({ success: false, error: 'No valid email addresses found in file' });
    }

    log('info', `Validating ${emails.length} emails (SMTP=${checkSmtp})`, { file: req.file.originalname });

    const emailsToProcess = emails.slice(0, 50000);

    const batchResults = await validateEmailBatch(emailsToProcess, {
      checkSmtp,
      checkDisposable: true,
      checkRoleBased: true,
      concurrency: checkSmtp ? 50 : 100,
      delayMs: 0
    });

    let valid_n = 0, invalid_n = 0, risky_n = 0, disposable_n = 0;
    const results = batchResults.map(r => {
      if (r.status === 'valid') valid_n++;
      else if (r.status === 'invalid') invalid_n++;
      else if (r.status === 'risky') risky_n++;
      if (!r.checks.disposable.passed) disposable_n++;

      // Build a meaningful reason label
      let reason = '';
      if (checkSmtp) {
        reason = r.checks.smtp.reason || '';
      }
      if (!reason) reason = r.checks.domain.reason || r.checks.disposable.reason || r.checks.syntax.reason || '';

      return {
        email: r.email,
        status: r.status,
        domain: r.email.split('@')[1] || '',
        has_mx: r.checks.domain.passed,
        is_disposable: !r.checks.disposable.passed,
        is_role_based: !r.checks.roleBased.passed,
        reason
      };
    });

    res.json({
      success: true,
      results,
      statistics: { total: results.length, valid: valid_n, invalid: invalid_n, risky: risky_n, disposable: disposable_n }
    });
  } catch (err) {
    log('error', 'Bulk validate error', { error: err.message });
    res.status(500).json({ success: false, error: err.message });
  }
});

// Test SMTP
app.post('/api/test-smtp', upload.none(), async (req, res) => {
  try {
    const host = req.body.host;
    const port = parseInt(req.body.port || '587');
    const username = (req.body.username || '').trim();
    const password = (req.body.password || '').trim();
    const use_tls = req.body.use_tls === 'true';
    const use_ssl = req.body.use_ssl === 'true';

    if (!host) {
      return res.status(400).json({ success: false, error: 'host is required' });
    }

    const smtpConfig = {
      host,
      port,
      secure: use_ssl,
      user: username,
      pass: password,
      provider: 'smtp'
    };

    const result = await testSMTPConnection(smtpConfig);
    if (result.success) {
      res.json({ success: true, message: `Connected to ${host}:${port} successfully` });
    } else {
      let errMsg = result.message || 'SMTP Connection failed';
      if (errMsg.includes('535') && host.includes('hostinger') && username.includes('oddinfotech.com')) {
        errMsg += ' (For Google Workspace / oddinfotech.com email, please set Host to smtp.gmail.com on Port 587)';
      }
      res.status(400).json({ success: false, error: errMsg });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Google Auth Verify ──
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ success: false, error: 'No credential provided' });

    // If no Google Client ID configured, allow any token (dev mode)
    if (!googleClient) {
      // Decode JWT payload without verification (dev/no-config mode)
      const parts = credential.split('.');
      if (parts.length < 2) return res.status(400).json({ success: false, error: 'Invalid token format' });
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      return res.json({ success: true, user: { name: payload.name, email: payload.email, picture: payload.picture } });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    res.json({ success: true, user: { name: payload.name, email: payload.email, picture: payload.picture } });
  } catch (err) {
    log('error', 'Google auth verify failed', { error: err.message });
    res.status(401).json({ success: false, error: 'Invalid Google token: ' + err.message });
  }
});

// Send Bulk Emails — Job-Based (async) to prevent 504 Gateway Timeout
// The old synchronous approach blocked the HTTP connection for minutes when
// sending 100s of emails, causing proxy 504 timeouts after only a few sends.
// Now we start the job immediately and return a jobId; the frontend polls progress.
app.post('/api/send', async (req, res) => {
  try {
    const {
      recipients,
      smtp_config,
      subject,
      body,
      message_plain,
      dry_run,
      images,
      attachments,
      rate,
      max_retries
    } = req.body;

    if (!recipients || !Array.isArray(recipients) || recipients.length === 0) {
      return res.status(400).json({ success: false, error: 'recipients list is required' });
    }

    if (dry_run) {
      return res.json({
        success: true,
        summary: {
          total: recipients.length,
          sent: recipients.length,
          failed: 0,
          dry_run: true
        }
      });
    }

    const host = smtp_config?.smtp_host || smtp_config?.host;
    if (!host) {
      return res.status(400).json({ success: false, error: 'SMTP host is required' });
    }

    // Create a job immediately and respond — processing happens in background
    const jobId = uuidv4();
    const job = {
      id: jobId,
      type: 'bulk-send',
      status: 'running',
      total: recipients.length,
      sent: 0,
      failed: 0,
      completed: 0,
      failed_emails: [],
      failed_reasons: {},
      results: [],
      startTime: Date.now()
    };
    jobs.set(jobId, job);

    log('info', `Starting async bulk-send job ${jobId}`, { count: recipients.length });

    // ── Process in background (does NOT block HTTP response) ──
    (async () => {
      try {
        const { html, attachments: mailerAttachments } = prepareEmailContent(body, message_plain, images, attachments);

        const transportConfig = {
          host: host,
          port: parseInt(smtp_config.smtp_port || smtp_config.port || '587'),
          secure: smtp_config.use_ssl || false,
          user: smtp_config.smtp_user || smtp_config.username || '',
          pass: smtp_config.smtp_pass || smtp_config.password || '',
          provider: 'smtp'
        };

        const transporter = createTransporter(transportConfig);
        const rawFromAddr = smtp_config.from_addr || transportConfig.user || 'sender@example.com';
        const replyToAddr = smtp_config.reply_to || smtp_config.replyTo || smtp_config.replyToEmail || undefined;

        // Clean subject line (strip duplicate "Subject: " prefix if present)
        const cleanSub = (subject || 'No Subject').replace(/^subject:\s*/i, '').trim() || 'No Subject';

        // Parse From Name & From Email for exact DMARC / SPF alignment
        let fromEmail = transportConfig.user || 'sarah@oddinfotech.com';
        let fromName = process.env.SMTP_FROM_NAME || 'oddinfotech';

        if (rawFromAddr.includes('<') && rawFromAddr.includes('>')) {
          const match = rawFromAddr.match(/(?:"?([^"]*)"?\s*)?<?([^>]+)>?/);
          if (match) {
            if (match[1]) fromName = match[1].trim();
            if (match[2]) fromEmail = match[2].trim();
          }
        } else if (rawFromAddr.includes('@')) {
          fromEmail = rawFromAddr.trim();
        }
        fromEmail = fromEmail.toLowerCase();
        fromName = fromName.replace(/"/g, '').trim();

        const formattedFromHeader = fromName ? `"${fromName}" <${fromEmail}>` : fromEmail;
        const senderDomain = fromEmail.includes('@') ? fromEmail.split('@')[1] : 'oddinfotech.com';

        const pLimit = require('p-limit');
        // SAFE rate for Google Workspace: max 3 concurrent + 1000ms pacing = ~3 emails/sec (~180/min)
        // This prevents Google account lockdown (Google locks accounts sending >500/day at burst rates)
        const concurrency = Math.min(Math.max(parseInt(req.body.concurrency || process.env.CONCURRENT_EMAILS || 3), 1), 5);
        const limit = pLimit(concurrency);
        const retries = parseInt(max_retries) || 2;
        const pacingDelayMs = 1000; // 1s inter-message pacing (critical for Google Workspace compliance)

        const tasks = recipients.map(email => limit(async () => {
          if (job.status === 'cancelled') return;

          const targetEmail = (email || '').trim().toLowerCase();
          if (!targetEmail || !targetEmail.includes('@')) return;

          let success = false;
          let lastError = 'Unknown error';
          const msgId = `<${uuidv4()}@${senderDomain}>`;

          for (let attempt = 1; attempt <= retries; attempt++) {
            try {
              await transporter.sendMail({
                from: formattedFromHeader,
                to: targetEmail,
                envelope: {
                  from: fromEmail,
                  to: targetEmail
                },
                messageId: msgId,
                ...(replyToAddr ? { replyTo: replyToAddr } : {}),
                subject: cleanSub,
                html: html,
                text: message_plain || stripHtml(html),
                attachments: mailerAttachments,
                headers: {
                  'X-Mailer': 'MailForge-Pro/2.0',
                  'X-Report-Abuse': `mailto:abuse@${senderDomain}`,
                  'List-Unsubscribe': `<mailto:unsubscribe@${senderDomain}?subject=unsubscribe>`,
                  'Precedence': 'bulk'
                }
              });
              success = true;
              break;
            } catch (err) {
              lastError = err.message;
              if (attempt < retries) {
                await new Promise(resolve => setTimeout(resolve, attempt * 200));
              }
            }
          }

          if (success) {
            job.sent++;
            job.results.push({ email: targetEmail, status: 'sent', timestamp: new Date().toISOString() });
          } else {
            job.failed++;
            job.failed_emails.push(targetEmail);
            job.failed_reasons[targetEmail] = lastError;
            job.results.push({ email: targetEmail, status: 'failed', error: lastError, timestamp: new Date().toISOString() });
          }
          job.completed = job.sent + job.failed;

          if (pacingDelayMs > 0) {
            await new Promise(resolve => setTimeout(resolve, pacingDelayMs));
          }
        }));

        await Promise.all(tasks);

        transporter.close();

        job.status = 'completed';
        job.endTime = Date.now();
        job.summary = {
          total: recipients.length,
          sent: job.sent,
          failed: job.failed,
          failed_emails: job.failed_emails,
          failed_reasons: job.failed_reasons,
          durationMs: job.endTime - job.startTime
        };

        // ── Persist results to send history for analytics ──
        try {
          const enrichedResults = job.results.map(r => ({
            ...r,
            reason: r.status === 'sent' ? 'Delivered successfully' : (job.failed_reasons[r.email] || r.error || 'Unknown'),
            smtpHost: host
          }));
          recordBatchResults(enrichedResults);
        } catch (histErr) {
          log('warn', 'Could not persist send history', { error: histErr.message });
        }

        log('info', `Bulk send job ${jobId} completed`, { sent: job.sent, failed: job.failed });
      } catch (err) {
        job.status = 'failed';
        job.error = err.message;
        log('error', `Bulk send job ${jobId} failed`, { error: err.message });
      }
    })();

    // ── Respond immediately with jobId ──
    res.json({
      success: true,
      jobId,
      message: `Sending ${recipients.length} emails in background`,
      status: 'started'
    });

  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Get Send Job Status (for polling) ──
app.get('/api/send-job/:jobId', (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Job not found' });

  res.json({
    id: job.id,
    type: job.type,
    status: job.status,
    total: job.total,
    sent: job.sent || 0,
    failed: job.failed || 0,
    completed: job.completed || 0,
    progress: job.total > 0 ? Math.round(((job.sent || 0) + (job.failed || 0)) / job.total * 100) : 0,
    elapsedMs: Date.now() - job.startTime,
    ...(job.status === 'completed' && { summary: job.summary }),
    ...(job.status === 'failed' && { error: job.error })
  });
});

// ── Analytics: Get aggregated send history stats ──
app.get('/api/analytics', (req, res) => {
  try {
    const period = req.query.period || 'daily';
    const data = getAnalytics(period);
    res.json({ success: true, ...data });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Analytics: Export filtered history as CSV or JSON ──
app.get('/api/analytics/export', (req, res) => {
  try {
    const period = req.query.period || 'daily';
    const format = req.query.format || 'csv';
    const { logs } = getAnalytics(period);
    const ts = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
    if (format === 'json') {
      res.setHeader('Content-Disposition', `attachment; filename="send_report_${period}_${ts}.json"`);
      res.setHeader('Content-Type', 'application/json');
      return res.send(JSON.stringify(logs, null, 2));
    }
    // Default: CSV
    const header = 'Email,Status,Reason,SMTP Host,Timestamp';
    const rows = logs.map(l =>
      `"${l.email}","${l.status}","${(l.reason || '').replace(/"/g, "'")}","${l.smtpHost || ''}","${l.timestamp || ''}"`
    );
    res.setHeader('Content-Disposition', `attachment; filename="send_report_${period}_${ts}.csv"`);
    res.setHeader('Content-Type', 'text/csv');
    return res.send([header, ...rows].join('\n'));
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Export Results
app.post('/api/export', async (req, res) => {
  try {
    const { results, format } = req.body;
    if (!results || !Array.isArray(results) || results.length === 0) {
      return res.status(400).json({ success: false, error: 'No results to export' });
    }

    const ts = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
    const filename = `validation_${ts}.${format === 'csv' ? 'csv' : 'json'}`;

    if (format === 'csv') {
      const csvContent = buildCSV(results);
      return res.json({ success: true, data: csvContent, filename });
    } else if (format === 'json') {
      return res.json({ success: true, data: results, filename });
    }

    res.status(400).json({ success: false, error: `Unsupported format: ${format}` });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── Helpers ───────────────────────────────────────────────────────────────
function buildValidationSummary(results) {
  return {
    total: results.length,
    valid: results.filter(r => r.status === 'valid').length,
    invalid: results.filter(r => r.status === 'invalid').length,
    risky: results.filter(r => r.status === 'risky').length,
    unknown: results.filter(r => r.status === 'unknown').length,
    averageScore: Math.round(results.reduce((s, r) => s + r.score, 0) / results.length),
    averageResponseMs: Math.round(results.reduce((s, r) => s + r.responseTimeMs, 0) / results.length)
  };
}

function buildCSV(results) {
  const headers = ['Email', 'Status', 'Domain', 'Has MX', 'Disposable', 'Role Based', 'Reason'];
  const rows = results.map(r => [
    r.email || '',
    r.status || '',
    r.domain || (r.email ? r.email.split('@')[1] : ''),
    r.has_mx !== undefined ? (r.has_mx ? 'Yes' : 'No') : (r.checks?.domain?.passed ? 'Yes' : 'No'),
    r.is_disposable !== undefined ? (r.is_disposable ? 'Yes' : 'No') : (r.checks?.disposable?.passed ? 'No' : 'Yes'),
    r.is_role_based !== undefined ? (r.is_role_based ? 'Yes' : 'No') : (r.checks?.roleBased?.passed ? 'No' : 'Yes'),
    r.reason || [r.checks?.syntax?.reason, r.checks?.domain?.reason, r.checks?.smtp?.reason].filter(Boolean).join('; ') || ''
  ].map(v => `"${String(v !== undefined && v !== null ? v : '').replace(/"/g, '""')}"`));

  return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
}

function buildBulkSendCSV(results) {
  const headers = ['Email', 'Status', 'Message ID / Error', 'Provider', 'Timestamp'];
  const rows = results.map(r => [
    r.email,
    r.status,
    r.messageId || r.error || '',
    r.provider,
    r.timestamp
  ].map(v => `"${String(v).replace(/"/g, '""')}"`));

  return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
}

function findEmailColumn(columns) {
  const emailCols = ['email', 'email_address', 'emailaddress', 'e-mail', 'mail', 'Email', 'EMAIL'];
  for (const col of emailCols) {
    if (columns.includes(col)) return col;
  }
  return columns[0];
}

// Express custom error handler for file uploads/other errors
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }
  if (err) {
    return res.status(400).json({ error: err.message });
  }
  next();
});

// ─── Start Server ──────────────────────────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log(`\n🚀 Email Validator & Bulk Sender running at http://localhost:${PORT}`);
  console.log(`📧 Daily quota: ${dailyQuota.max} emails/day`);
  console.log(`⚡ Concurrent sends: ${process.env.CONCURRENT_EMAILS || 3}\n`);
});

server.timeout = 600000;         // 10 minutes timeout for bulk operations
server.keepAliveTimeout = 600000; // 10 minutes keep-alive

module.exports = app;
