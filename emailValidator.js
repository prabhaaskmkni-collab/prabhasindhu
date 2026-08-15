/**
 * Email Validator Module
 * Performs multi-layer validation: syntax, MX record, disposable check, SMTP ping
 */

const dns = require('dns').promises;
const net = require('net');
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

// ─── Disposable Email Domains (common ones) ────────────────────────────────
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com', 'guerrillamail.com', 'tempmail.com', 'throwaway.email',
  'yopmail.com', '10minutemail.com', 'trashmail.com', 'maildrop.cc',
  'sharklasers.com', 'guerrillamailblock.com', 'grr.la', 'guerrillamail.info',
  'guerrillamail.biz', 'guerrillamail.de', 'guerrillamail.net', 'guerrillamail.org',
  'spam4.me', 'binkmail.com', 'bob.email', 'discard.email', 'discardmail.com',
  'fakeinbox.com', 'filzmail.com', 'getairmail.com', 'gishpuppy.com',
  'humaility.com', 'junk1.com', 'kasmail.com', 'klassmaster.com',
  'klzlk.com', 'letthemeatspam.com', 'lol.ovpn.to', 'lortemail.dk',
  'meltmail.com', 'moburl.com', 'mytrashmail.com', 'netviewer-france.com',
  'neverbox.com', 'nobulk.com', 'noclickemail.com', 'nogmailspam.info',
  'nomail.xl.cx', 'nomail2me.com', 'nospamfor.us', 'nospammail.net',
  'objectmail.com', 'obobbo.com', 'odaymail.com', 'oneoffemail.com',
  'poofy.org', 'pookmail.com', 'rklips.com', 'rmqkr.net',
  'rppkn.com', 'rtrtr.com', 's0ny.net', 'safe-mail.net',
  'sandelf.de', 'saynotospams.com', 'selfdestructingmail.com', 'sendspamhere.com',
  'shieldedmail.com', 'sinnlos-mail.de', 'slopsbox.com', 'smapfree24.com',
  'spambin.com', 'spamcon.org', 'spamcorptastic.com', 'spamcowboy.com',
  'spamday.com', 'spamex.com', 'spamfree.eu', 'spamgourmet.com',
  'spamherelots.com', 'spaml.com', 'spammotel.com', 'spamoff.de',
  'spamslicer.com', 'spamspot.com', 'spamthis.co.uk', 'spamtrail.com',
  'speed.1s.fr', 'superrito.com', 'suremail.info', 'sweetxxx.de',
  'tafmail.com', 'teleworm.us', 'tempalias.com', 'tempe-mail.com',
  'tempemail.biz', 'tempemail.com', 'tempemail.net', 'tempinbox.co.uk',
  'tempinbox.com', 'tempmailer.com', 'trashmail.at', 'trashmail.io',
  'trashmail.me', 'trashmail.net', 'trbvm.com', 'turual.com',
  'uggsrock.com', 'uroid.com', 'veryrealemail.com', 'viditag.com',
  'viewcastmedia.com', 'viewcastmedia.net', 'viewcastmedia.org'
]);

// ─── Role-based Email Prefixes ─────────────────────────────────────────────
const ROLE_BASED_PREFIXES = new Set([
  'admin', 'administrator', 'webmaster', 'hostmaster', 'postmaster',
  'noreply', 'no-reply', 'donotreply', 'do-not-reply', 'mailer-daemon',
  'support', 'help', 'info', 'contact', 'sales', 'billing',
  'abuse', 'spam', 'security', 'privacy', 'legal', 'marketing',
  'newsletter', 'news', 'notifications', 'alerts', 'team', 'office'
]);

// ─── Syntax Validation ─────────────────────────────────────────────────────
function validateSyntax(email) {
  const result = { valid: false, reason: '' };

  if (!email || typeof email !== 'string') {
    result.reason = 'Email is empty or not a string';
    return result;
  }

  const trimmed = email.trim().toLowerCase();

  // Basic length check
  if (trimmed.length > 320) {
    result.reason = 'Email too long (max 320 characters)';
    return result;
  }

  // RFC 5322 compliant regex
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

  if (!emailRegex.test(trimmed)) {
    result.reason = 'Invalid email format';
    return result;
  }

  const [localPart, domain] = trimmed.split('@');

  // Local part checks
  if (localPart.length > 64) {
    result.reason = 'Local part too long (max 64 characters)';
    return result;
  }
  if (localPart.startsWith('.') || localPart.endsWith('.')) {
    result.reason = 'Local part cannot start or end with a dot';
    return result;
  }
  if (localPart.includes('..')) {
    result.reason = 'Local part cannot have consecutive dots';
    return result;
  }

  // Domain checks
  if (domain.length > 255) {
    result.reason = 'Domain too long';
    return result;
  }
  if (domain.startsWith('-') || domain.endsWith('-')) {
    result.reason = 'Domain cannot start or end with a hyphen';
    return result;
  }

  result.valid = true;
  result.normalizedEmail = trimmed;
  return result;
}

// ─── DNS-over-HTTPS MX Helpers ─────────────────────────────────────────────
async function checkMXRecordDoH(domain) {
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`;
    const res = await fetch(url, {
      headers: { 'accept': 'application/dns-json' }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    
    if (data.Answer && data.Answer.length > 0) {
      const records = data.Answer
        .filter(ans => ans.type === 15) // MX type
        .map(ans => {
          const parts = ans.data.split(' ');
          return {
            priority: parseInt(parts[0]),
            exchange: parts[1].replace(/\.$/, '')
          };
        });
      
      if (records.length > 0) {
        return {
          valid: true,
          mxRecords: records.sort((a, b) => a.priority - b.priority)
        };
      }
    }
    return await checkMXRecordGoogleDoH(domain);
  } catch (err) {
    return await checkMXRecordGoogleDoH(domain);
  }
}

async function checkMXRecordGoogleDoH(domain) {
  try {
    const url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    
    if (data.Answer && data.Answer.length > 0) {
      const records = data.Answer
        .filter(ans => ans.type === 15)
        .map(ans => {
          const parts = ans.data.split(' ');
          return {
            priority: parseInt(parts[0]),
            exchange: parts[1].replace(/\.$/, '')
          };
        });
      
      if (records.length > 0) {
        return {
          valid: true,
          mxRecords: records.sort((a, b) => a.priority - b.priority)
        };
      }
    }
    return { valid: false, reason: 'No MX records found for domain', mxRecords: [] };
  } catch (err) {
    return { valid: false, reason: `DoH MX lookup failed: ${err.message}`, mxRecords: [] };
  }
}

// ─── MX Record Check ───────────────────────────────────────────────────────
const mxCache = new Map();

async function checkMXRecord(domain) {
  const cleanDomain = domain.trim().toLowerCase();
  if (mxCache.has(cleanDomain)) {
    return mxCache.get(cleanDomain);
  }

  const resolveAndCache = async () => {
    try {
      const records = await Promise.race([
        dns.resolveMx(cleanDomain),
        new Promise((_, reject) => setTimeout(() => reject(new Error('MX lookup timeout')), 8000))
      ]);

      if (!records || records.length === 0) {
        return { valid: false, reason: 'No MX records found for domain', mxRecords: [] };
      }

      const sorted = records.sort((a, b) => a.priority - b.priority);
      return {
        valid: true,
        mxRecords: sorted.map(r => ({ exchange: r.exchange, priority: r.priority }))
      };
    } catch (err) {
      if (err.code === 'ENOTFOUND' || err.code === 'ENODATA') {
        return { valid: false, reason: 'Domain does not exist', mxRecords: [] };
      }
      console.log(`[DNS Warning] Standard MX lookup failed for ${cleanDomain} (${err.message}). Trying DNS-over-HTTPS fallback...`);
      return await checkMXRecordDoH(cleanDomain);
    }
  };

  const result = await resolveAndCache();
  mxCache.set(cleanDomain, result);
  return result;
}

// ─── SMTP Connection Test ──────────────────────────────────────────────────
function smtpPing(mxHost, email, customTimeout = 10000) {
  return new Promise((resolve) => {
    const timeout = customTimeout;
    let resolved = false;

    const done = (result) => {
      if (!resolved) {
        resolved = true;
        clearTimeout(timer);
        socket.destroy();
        resolve(result);
      }
    };

    const timer = setTimeout(() => {
      done({ valid: null, reason: 'SMTP connection timed out', smtpReachable: false });
    }, timeout);

    const socket = net.createConnection({ host: mxHost, port: 25 }, () => {
      // Connection established
    });

    let step = 0;
    let buffer = '';

    socket.on('data', (data) => {
      buffer += data.toString();
      const lines = buffer.split('\r\n');
      buffer = lines.pop(); // Keep incomplete line

      for (const line of lines) {
        if (!line) continue;
        const code = parseInt(line.substring(0, 3));

        if (step === 0 && code === 220) {
          // Server greeting
          socket.write(`EHLO emailvalidator.local\r\n`);
          step = 1;
        } else if (step === 1 && (code === 250 || code === 220)) {
          // EHLO response - send MAIL FROM
          socket.write(`MAIL FROM:<validator@emailvalidator.local>\r\n`);
          step = 2;
        } else if (step === 2 && code === 250) {
          // MAIL FROM accepted - send RCPT TO
          socket.write(`RCPT TO:<${email}>\r\n`);
          step = 3;
        } else if (step === 3) {
          if (code === 250 || code === 251) {
            done({ valid: true, reason: 'SMTP verification passed', smtpReachable: true, smtpCode: code });
          } else if (code === 550 || code === 551 || code === 553 || code === 554) {
            done({ valid: false, reason: `Email rejected by server (${code})`, smtpReachable: true, smtpCode: code });
          } else if (code === 421 || code === 450 || code === 451 || code === 452) {
            done({ valid: null, reason: `Server temporarily unavailable (${code})`, smtpReachable: true, smtpCode: code });
          } else {
            done({ valid: null, reason: `Unknown SMTP response (${code})`, smtpReachable: true, smtpCode: code });
          }
          socket.write(`QUIT\r\n`);
          step = 4;
        } else if (step === 2 && code !== 250) {
          done({ valid: null, reason: `SMTP MAIL FROM rejected (${code})`, smtpReachable: true, smtpCode: code });
        }
      }
    });

    socket.on('error', (err) => {
      done({ valid: null, reason: `SMTP connection error: ${err.message}`, smtpReachable: false });
    });

    socket.on('close', () => {
      if (!resolved) {
        done({ valid: null, reason: 'SMTP connection closed unexpectedly', smtpReachable: false });
      }
    });
  });
}

// ─── Main Validation Function ──────────────────────────────────────────────
async function validateEmail(email, options = {}) {
  const { checkSmtp = true, checkDisposable = true, checkRoleBased = false } = options;

  const startTime = Date.now();
  const result = {
    email: email?.trim()?.toLowerCase() || '',
    valid: false,
    score: 0,           // 0-100 confidence score
    status: 'unknown',  // valid, invalid, risky, unknown
    checks: {
      syntax: { passed: false, reason: '' },
      domain: { passed: false, reason: '', mxRecords: [] },
      disposable: { passed: true, reason: '' },
      roleBased: { passed: true, reason: '' },
      smtp: { passed: false, reason: '', reachable: false }
    },
    suggestions: [],
    validatedAt: new Date().toISOString(),
    responseTimeMs: 0
  };

  // ── Step 1: Syntax Check ──
  const syntaxCheck = validateSyntax(email);
  result.checks.syntax.passed = syntaxCheck.valid;
  result.checks.syntax.reason = syntaxCheck.reason || 'Valid syntax';

  if (!syntaxCheck.valid) {
    result.status = 'invalid';
    result.valid = false;
    result.score = 0;
    result.responseTimeMs = Date.now() - startTime;

    // Offer suggestions for common typos
    if (email && email.includes('@')) {
      const domain = email.split('@')[1]?.toLowerCase();
      const commonDomains = { 'gmai.com': 'gmail.com', 'gmial.com': 'gmail.com', 'hotmial.com': 'hotmail.com', 'yahooo.com': 'yahoo.com', 'outllok.com': 'outlook.com' };
      if (commonDomains[domain]) result.suggestions.push(`Did you mean: ${email.split('@')[0]}@${commonDomains[domain]}?`);
    }

    return result;
  }

  const [localPart, domain] = syntaxCheck.normalizedEmail.split('@');
  result.email = syntaxCheck.normalizedEmail;
  result.score += 20; // Syntax passed

  // ── Step 2: Disposable Email Check ──
  if (checkDisposable && DISPOSABLE_DOMAINS.has(domain)) {
    result.checks.disposable.passed = false;
    result.checks.disposable.reason = 'Disposable/temporary email address detected';
    result.status = 'invalid';
    result.valid = false;
    result.score = 10;
    result.responseTimeMs = Date.now() - startTime;
    return result;
  }
  result.checks.disposable.reason = 'Not a disposable domain';
  result.score += 10;

  // ── Step 3: Role-based Check ──
  if (checkRoleBased && ROLE_BASED_PREFIXES.has(localPart)) {
    result.checks.roleBased.passed = false;
    result.checks.roleBased.reason = 'Role-based email address (may have low deliverability)';
    result.suggestions.push('Role-based emails often have lower engagement rates');
  } else {
    result.checks.roleBased.reason = 'Not a role-based address';
  }

  // ── Step 4: MX Record Check ──
  const mxCheck = await checkMXRecord(domain);
  result.checks.domain.passed = mxCheck.valid;
  result.checks.domain.reason = mxCheck.reason || 'Valid MX records found';
  result.checks.domain.mxRecords = mxCheck.mxRecords || [];

  if (!mxCheck.valid) {
    const isResolverErr = mxCheck.reason.includes('failed') || mxCheck.reason.includes('timeout');
    if (isResolverErr) {
      result.status = 'unknown';
      result.valid = true;
      result.score = 50; // Syntax is correct, but DNS resolver blocked/failed
      result.responseTimeMs = Date.now() - startTime;
      return result;
    } else {
      result.status = 'invalid';
      result.valid = false;
      result.score = Math.max(result.score, 20);
      result.responseTimeMs = Date.now() - startTime;
      return result;
    }
  }
  result.score += 30; // MX records found

  // ── Step 5: SMTP Verification ──
  if (checkSmtp && mxCheck.mxRecords.length > 0) {
    const primaryMX = mxCheck.mxRecords[0].exchange;
    try {
      const smtpTimeout = options.smtpTimeout || 10000;
      const smtpResult = await smtpPing(primaryMX, result.email, smtpTimeout);
      result.checks.smtp.reachable = smtpResult.smtpReachable;
      result.checks.smtp.smtpCode = smtpResult.smtpCode;

      if (smtpResult.valid === true) {
        result.checks.smtp.passed = true;
        result.checks.smtp.reason = 'SMTP verification successful';
        result.score += 40;
        result.status = 'valid';
        result.valid = true;
      } else if (smtpResult.valid === false) {
        result.checks.smtp.passed = false;
        result.checks.smtp.reason = smtpResult.reason;
        result.status = 'invalid';
        result.valid = false;
      } else {
        // null = unknown/greylisted/connection issue
        result.checks.smtp.passed = false;
        result.checks.smtp.reason = smtpResult.reason;
        
        // If SMTP server is unreachable (port blocked, timeout, rate limited/refused connection),
        // we should not mark the email as risky since the domain MX records are valid.
        if (smtpResult.smtpReachable === false) {
          result.status = 'valid';
          result.valid = true;
          result.score += 25;
          result.checks.smtp.reason = `MX records valid (SMTP check unreachable/timeout)`;
        } else {
          result.status = 'risky';
          result.valid = true; // Assume valid but risky
          result.score += 20;
          result.suggestions.push('SMTP verification inconclusive - email may still be valid');
        }
      }
    } catch (err) {
      result.checks.smtp.reason = `SMTP check error: ${err.message}`;
      result.status = 'valid';
      result.valid = true;
      result.score += 25;
      result.checks.smtp.reason = `MX records valid (SMTP check error)`;
    }
  } else if (!checkSmtp) {
    // Skip SMTP, give partial score
    result.score += 25;
    result.status = result.score >= 75 ? 'valid' : 'risky';
    result.valid = result.score >= 50;
    result.checks.smtp.reason = 'SMTP check skipped';
  }

  // Final score clamp
  result.score = Math.min(100, Math.max(0, result.score));

  // Do not override valid status for role-based emails. They are active mailboxes.

  result.responseTimeMs = Date.now() - startTime;
  return result;
}

const pLimit = require('p-limit');

// ─── Batch Validation ─────────────────────────────────────────────────────
async function validateEmailBatch(emails, options = {}, onProgress = null) {
  const defaultConcurrency = options.checkSmtp ? 50 : 100;
  const concurrency = options.concurrency || defaultConcurrency;
  const limit = pLimit(concurrency);
  const total = emails.length;
  let completed = 0;

  const tasks = emails.map(email => limit(async () => {
    const r = await validateEmail(email, options);
    completed++;
    if (onProgress) onProgress(completed, total, r);
    return r;
  }));

  return await Promise.all(tasks);
}

module.exports = { validateEmail, validateEmailBatch, validateSyntax, checkMXRecord };
