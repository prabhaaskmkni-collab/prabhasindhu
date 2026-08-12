/**
 * SMTP Mailer & Bulk Email Sender
 * Handles SMTP config, connection testing, and concurrent bulk sending
 * Now supports: Direct SMTP + SendGrid API
 */

const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

// ─── SendGrid API Helper ───────────────────────────────────────────────────
async function sendViaSendGrid(mailOptions, fromConfig = {}) {
  const SENDGRID_API_KEY = fromConfig.apiKey || process.env.SENDGRID_API_KEY;

  if (!SENDGRID_API_KEY || SENDGRID_API_KEY === 'YOUR_SENDGRID_API_KEY_HERE') {
    throw new Error('SendGrid API key is not configured. Please enter your API key.');
  }

  const fromName  = fromConfig.fromName  || process.env.SENDGRID_FROM_NAME  || process.env.SMTP_FROM_NAME  || 'Sender';
  const fromEmail = fromConfig.fromEmail || process.env.SENDGRID_FROM_EMAIL || process.env.SMTP_FROM_EMAIL;

  if (!fromEmail) {
    throw new Error('Sender email is required. Set SENDGRID_FROM_EMAIL in .env');
  }

  const payload = {
    personalizations: [{ to: [{ email: mailOptions.to }] }],
    from: { email: fromEmail, name: fromName },
    subject: mailOptions.subject,
    content: []
  };

  if (mailOptions.text) payload.content.push({ type: 'text/plain', value: mailOptions.text });
  if (mailOptions.html) payload.content.push({ type: 'text/html',  value: mailOptions.html  });
  if (!payload.content.length) payload.content.push({ type: 'text/plain', value: '' });

  if (mailOptions.replyTo) payload.reply_to = { email: mailOptions.replyTo };

  const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
  const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
    method:  'POST',
    headers: {
      'Authorization': `Bearer ${SENDGRID_API_KEY}`,
      'Content-Type':  'application/json'
    },
    body: JSON.stringify(payload)
  });

  if (response.status === 202) {
    return {
      success:   true,
      messageId: response.headers.get('x-message-id') || `sg-${Date.now()}`,
      to:        mailOptions.to,
      response:  'SendGrid accepted (202)'
    };
  }

  // Parse error body
  let errBody = {};
  try { errBody = await response.json(); } catch (_) {}
  const errMsg = errBody?.errors?.[0]?.message || `SendGrid HTTP ${response.status}`;
  throw new Error(errMsg);
}

// ─── SendGrid API Connection Test Helper ────────────────────────────────────
async function testSendGridConnection(apiKey) {
  try {
    const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));
    const response = await fetch('https://api.sendgrid.com/v3/scopes', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${apiKey}`
      }
    });
    if (response.status === 200) {
      return { success: true, message: 'SendGrid API key verified successfully' };
    } else {
      let errBody = {};
      try { errBody = await response.json(); } catch (_) {}
      const errMsg = errBody?.errors?.[0]?.message || `HTTP ${response.status}`;
      return { success: false, message: `SendGrid verification failed: ${errMsg}` };
    }
  } catch (err) {
    return { success: false, message: `SendGrid connection error: ${err.message}` };
  }
}

// ─── Daily Quota Tracker ───────────────────────────────────────────────────
const dailyQuota = {
  count: 0,
  date: new Date().toDateString(),
  max: 99999999,

  reset() {
    this.count = 0;
  },
  canSend(n = 1)   { return true; },
  increment(n = 1) { this.count += n; },
  remaining()      { return 99999999; },
  stats() {
    return {
      sent:        this.count,
      remaining:   99999999,
      max:         99999999,
      date:        new Date().toDateString(),
      percentUsed: 0
    };
  }
};

// ─── AWS SES SMTP Password Generator ────────────────────────────────────────
function getSmtpPassword(secretAccessKey, region) {
  const DATE = "11111111";
  const SERVICE = "ses";
  const TERMINAL = "aws4_request";
  const MESSAGE = "SendRawEmail";
  const VERSION = 0x04;

  const sign = (key, msg) => {
    return crypto.createHmac('sha256', key).update(msg).digest();
  };

  let signature = sign(`AWS4${secretAccessKey}`, DATE);
  signature = sign(signature, region);
  signature = sign(signature, SERVICE);
  signature = sign(signature, TERMINAL);
  signature = sign(signature, MESSAGE);

  const signatureAndVersion = Buffer.concat([
    Buffer.from([VERSION]),
    signature
  ]);

  return signatureAndVersion.toString('base64');
}

// ─── SMTP Transporter Factory ──────────────────────────────────────────────
function createTransporter(config = {}) {
  const provider = (config.provider || process.env.SEND_PROVIDER || 'smtp').toLowerCase();

  let host = config.host || process.env.SMTP_HOST || 'smtp.gmail.com';
  let port = parseInt(config.port || process.env.SMTP_PORT || 587);
  let secure = (config.secure !== undefined ? config.secure : process.env.SMTP_SECURE === 'true');
  let user = config.user || process.env.SMTP_USER;
  let pass = config.pass || process.env.SMTP_PASS;

  if (provider === 'ses') {
    const region = config.awsRegion || process.env.AWS_REGION || 'us-east-1';
    host = `email-smtp.${region}.amazonaws.com`;
    port = 587;
    secure = false; // secure: false for STARTTLS (587)
    
    const accessKeyId = config.awsAccessKeyId || process.env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = config.awsSecretAccessKey || process.env.AWS_SECRET_ACCESS_KEY;

    if (!accessKeyId || accessKeyId === 'YOUR_AWS_ACCESS_KEY_ID_HERE') {
      throw new Error('AWS Access Key ID is not configured. Please check your settings.');
    }
    if (!secretAccessKey || secretAccessKey === 'YOUR_AWS_SECRET_ACCESS_KEY_HERE') {
      throw new Error('AWS Secret Access Key is not configured. Please check your settings.');
    }

    user = accessKeyId;
    pass = getSmtpPassword(secretAccessKey, region);
  }

  user = user ? user.trim() : '';
  pass = pass ? pass.trim().replace(/\s+/g, '') : '';

  const smtpConfig = {
    host,
    port,
    secure,
    auth: {
      user,
      pass
    },
    tls:               { rejectUnauthorized: false },
    connectionTimeout: 10000,   // 10s — connection establish timeout
    greetingTimeout:   10000,   // 10s — greeting timeout
    socketTimeout:     30000,   // 30s — data upload timeout
    pool:              true,    // Pool connections for maximum performance
    maxConnections:    15,      // 15 concurrent SMTP sockets (balanced speed & deliverability)
    maxMessages:       1000     // Up to 1000 messages per socket connection
  };
  return nodemailer.createTransport(smtpConfig);
}

// ─── Test SMTP Connection ──────────────────────────────────────────────────
async function testSMTPConnection(config = {}) {
  const transporter = createTransporter(config);
  try {
    await transporter.verify();
    transporter.close();

    const provider = (config.provider || process.env.SEND_PROVIDER || 'smtp').toLowerCase();
    let displayHost = config.host || process.env.SMTP_HOST;
    let displayUser = config.user || process.env.SMTP_USER;

    if (provider === 'ses') {
      const region = config.awsRegion || process.env.AWS_REGION || 'us-east-1';
      displayHost = `email-smtp.${region}.amazonaws.com`;
      displayUser = config.awsAccessKeyId || process.env.AWS_ACCESS_KEY_ID;
    }

    return {
      success: true,
      message: 'SMTP connection verified successfully',
      host:    displayHost,
      port:    config.port || (provider === 'ses' ? 587 : process.env.SMTP_PORT),
      user:    displayUser
    };
  } catch (err) {
    transporter.close();
    return { success: false, message: err.message, code: err.code };
  }
}

// ─── Send Single Email (SMTP) ──────────────────────────────────────────────
async function sendEmail(transporter, mailOptions, fromConfig = {}) {
  const provider = (fromConfig.provider || process.env.SEND_PROVIDER || 'smtp').toLowerCase();

  let from;
  let fromEmail;

  if (provider === 'ses') {
    from = fromConfig.fromName || process.env.AWS_FROM_NAME || process.env.SMTP_FROM_NAME || 'Sender';
    fromEmail = fromConfig.fromEmail || process.env.AWS_FROM_EMAIL || process.env.SMTP_FROM_EMAIL;
  } else {
    from = fromConfig.fromName || process.env.SMTP_FROM_NAME;
    fromEmail = fromConfig.fromEmail || process.env.SMTP_FROM_EMAIL || fromConfig.user || process.env.SMTP_USER;
  }

  if (!fromEmail) {
    throw new Error('Sender email is required. Set from address in configuration.');
  }

  const placeholders = [
    'your-verified-email@yourdomain.com',
    'your-email@gmail.com',
    'your-email@outlook.com',
    'your-email@yahoo.com',
    'noreply@yourdomain.com'
  ];
  if (placeholders.includes(fromEmail.toLowerCase().trim())) {
    throw new Error(`The sender email "${fromEmail}" is a configuration placeholder. Please open the "SMTP Config" tab or edit your .env file, and set the "From Email" to your actual verified email address.`);
  }

  // Generate valid Message-ID & anti-spam headers
  const domain = fromEmail.includes('@') ? fromEmail.split('@')[1] : 'oddinfotech.site';
  const messageIdHost = domain.trim();

  const cleanFrom = (from || process.env.SMTP_FROM_NAME || 'oddinfotech').replace(/"/g, '').trim();
  const cleanFromEmail = fromEmail.trim().toLowerCase();
  const formattedFrom = cleanFrom ? `"${cleanFrom}" <${cleanFromEmail}>` : cleanFromEmail;
  const cleanSubject = (mailOptions.subject || 'No Subject').replace(/^subject:\s*/i, '').trim() || 'No Subject';

  const message = {
    from:     formattedFrom,
    to:       mailOptions.to,
    envelope: {
      from: cleanFromEmail,
      to: mailOptions.to
    },
    messageId: `<${Date.now()}-${Math.random().toString(36).substring(2, 9)}@${messageIdHost}>`,
    subject:  cleanSubject,
    text:     mailOptions.text || stripHtml(mailOptions.html || ''),
    html:     mailOptions.html || '',
    ...(mailOptions.replyTo  && { replyTo: mailOptions.replyTo }),
    ...(mailOptions.cc       && { cc:      mailOptions.cc      }),
    ...(mailOptions.bcc      && { bcc:     mailOptions.bcc     }),
    headers: {
      'X-Mailer':             'MailForge-Pro/2.0',
      'X-Report-Abuse':       `mailto:abuse@${messageIdHost}`,
      'List-Unsubscribe':     `<mailto:unsubscribe@${messageIdHost}?subject=unsubscribe>`,
      'Precedence':           'bulk',
      ...(mailOptions.headers || {})
    }
  };

  const info = await transporter.sendMail(message);
  return { success: true, messageId: info.messageId, to: mailOptions.to, response: info.response };
}

async function sendBulkEmails(emailList, template, smtpConfig = {}, onProgress = null) {
  const batchDelay  = parseInt(process.env.BATCH_DELAY_MS)    || 0;

  // Determine which provider to use
  // Priority: explicit provider in smtpConfig > env SEND_PROVIDER > 'smtp'
  const provider = (smtpConfig.provider || process.env.SEND_PROVIDER || 'smtp').toLowerCase();
  const useSendGrid = (provider === 'sendgrid');

  if (!dailyQuota.canSend(emailList.length)) {
    throw new Error(
      `Daily quota exceeded. Remaining: ${dailyQuota.remaining()} emails. ` +
      `Requested: ${emailList.length}`
    );
  }

  // Only create SMTP transporter when not using SendGrid
  const transporter = useSendGrid ? null : createTransporter(smtpConfig);

  const results = {
    total:     emailList.length,
    sent:      0,
    failed:    0,
    skipped:   0,
    provider:  provider,
    details:   [],
    startTime: new Date().toISOString(),
    endTime:   null,
    durationMs: 0
  };

  const pLimit = require('p-limit');
  const concurrency = parseInt(process.env.CONCURRENT_EMAILS) || 30;
  const limit = pLimit(concurrency);

  const tasks = emailList.map(recipient => limit(async () => {
    const mailOptions = {
      to:       recipient.email,
      subject:  personalizeTemplate(template.subject, recipient),
      html:     personalizeTemplate(template.html || template.body, recipient),
      text:     personalizeTemplate(template.text || stripHtml(template.html || template.body), recipient),
      replyTo:  template.replyTo,
      headers:  template.headers
    };

    try {
      let sendResult;

      if (useSendGrid) {
        // ── SendGrid API path ──
        sendResult = await sendViaSendGrid(mailOptions, smtpConfig);
      } else {
        // ── Direct SMTP / SES path ──
        sendResult = await sendEmail(transporter, mailOptions, smtpConfig);
      }

      dailyQuota.increment(1);
      results.sent++;

      const detail = {
        email:     recipient.email,
        status:    'sent',
        messageId: sendResult.messageId,
        provider:  provider,
        timestamp: new Date().toISOString()
      };
      results.details.push(detail);
      if (onProgress) onProgress({ type: 'sent', detail, stats: results });
      return detail;

    } catch (err) {
      results.failed++;
      const detail = {
        email:     recipient.email,
        status:    'failed',
        error:     err.message,
        provider:  provider,
        timestamp: new Date().toISOString()
      };
      results.details.push(detail);
      if (onProgress) onProgress({ type: 'failed', detail, stats: results });
      return detail;
    }
  }));

  await Promise.all(tasks);

  if (transporter) transporter.close();

  results.endTime   = new Date().toISOString();
  results.durationMs = Date.now() - startTs;

  return results;
}

// ─── Template Personalization ──────────────────────────────────────────────
function personalizeTemplate(template, recipient) {
  if (!template) return '';
  let result = template;
  const vars = {
    '{{name}}':            recipient.name || '',
    '{{first_name}}':      (recipient.name || '').split(' ')[0] || '',
    '{{last_name}}':       (recipient.name || '').split(' ').slice(1).join(' ') || '',
    '{{email}}':           recipient.email || '',
    '{{company}}':         recipient.company || '',
    '{{phone}}':           recipient.phone || '',
    '{{date}}':            new Date().toLocaleDateString(),
    '{{unsubscribe_link}}': recipient.unsubscribeLink || '#unsubscribe',
    ...Object.fromEntries(
      Object.entries(recipient.custom || {}).map(([k, v]) => [`{{${k}}}`, v])
    )
  };
  for (const [placeholder, value] of Object.entries(vars)) {
    result = result.replaceAll(placeholder, value);
  }
  return result;
}

// ─── Strip HTML Helper ─────────────────────────────────────────────────────
function stripHtml(html) {
  if (!html) return '';
  return html.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
}

// ─── Get SMTP/Provider Presets ─────────────────────────────────────────────
function getSMTPPresets() {
  return [
    {
      id: 'sendgrid-api', name: 'SendGrid (API — Recommended for 3000/day)',
      provider: 'sendgrid',
      notes: 'Uses SendGrid REST API. Set SENDGRID_API_KEY and SENDGRID_FROM_EMAIL in .env. Best deliverability.',
      docsUrl: 'https://docs.sendgrid.com/for-developers/sending-email/api-getting-started'
    },
    {
      id: 'ses-api', name: 'Amazon SES (API Credentials)',
      provider: 'ses',
      notes: 'Uses AWS Access Key ID & Secret Key to send bulk emails (likely 5000/day). Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env.',
      docsUrl: 'https://docs.aws.amazon.com/ses/latest/dg/send-email-api.html'
    },
    {
      id: 'gmail', name: 'Gmail',
      host: 'smtp.gmail.com', port: 587, secure: false,
      notes: 'Enable 2FA and use an App Password (not your regular password)',
      docsUrl: 'https://support.google.com/accounts/answer/185833'
    },
    {
      id: 'outlook', name: 'Outlook / Hotmail',
      host: 'smtp-mail.outlook.com', port: 587, secure: false,
      notes: 'Use your full Outlook email as username'
    },
    {
      id: 'yahoo', name: 'Yahoo Mail',
      host: 'smtp.mail.yahoo.com', port: 587, secure: false,
      notes: 'Generate an App Password in your Yahoo Account Security settings'
    },
    {
      id: 'sendgrid-smtp', name: 'SendGrid (SMTP)',
      host: 'smtp.sendgrid.net', port: 587, secure: false,
      notes: 'Use "apikey" as username and your SendGrid API key as password'
    },
    {
      id: 'mailgun', name: 'Mailgun',
      host: 'smtp.mailgun.org', port: 587, secure: false,
      notes: 'Use your Mailgun SMTP credentials from the dashboard'
    },
    {
      id: 'zoho', name: 'Zoho Mail',
      host: 'smtp.zoho.com', port: 587, secure: false,
      notes: 'Use your full Zoho email and password'
    },
    {
      id: 'office365', name: 'Office 365',
      host: 'smtp.office365.com', port: 587, secure: false,
      notes: 'Use your full Office 365 email and password'
    },
    {
      id: 'ses', name: 'Amazon SES (SMTP)',
      host: 'email-smtp.us-east-1.amazonaws.com', port: 587, secure: false,
      notes: 'Use your SES SMTP credentials (not raw AWS access keys)'
    }
  ];
}

module.exports = {
  createTransporter,
  testSMTPConnection,
  testSendGridConnection,
  sendEmail,
  sendViaSendGrid,
  sendBulkEmails,
  personalizeTemplate,
  dailyQuota,
  getSMTPPresets
};
