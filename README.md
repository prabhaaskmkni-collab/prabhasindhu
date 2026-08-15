# EmailPulse — Email Validator & Bulk Sender

A production-ready email validation and bulk email marketing tool built with Node.js.

## Features

### Email Validation
- **Syntax validation** — RFC 5322 compliant regex with detailed error messages
- **Domain/MX record check** — DNS lookup for valid mail exchanger records
- **Disposable email detection** — 100+ known temporary email domains blocked
- **SMTP verification** — Actually pings the mail server to verify the address exists
- **Role-based email detection** — Flags admin@, noreply@, support@, etc.
- **Confidence scoring** — 0–100 score based on all checks combined
- **Bulk validation** — Up to 3,000 emails with 3 concurrent validations
- **CSV export** — Download results filtered by valid/invalid/risky
- **File upload** — Accepts .csv and .txt files

### Bulk Email Sending
- **3 concurrent sends** per batch (configurable)
- **3,000 emails/day** quota with real-time tracking
- **Template personalization** — `{{name}}`, `{{email}}`, `{{company}}`, etc.
- **HTML + plain text** email support
- **SMTP pooling** — Connection reuse for performance
- **Live progress tracking** — Real-time job status updates
- **Send reports** — Full log of sent/failed per recipient

### SMTP Support
- Gmail, Outlook, Yahoo, Zoho, SendGrid, Mailgun, Amazon SES, Office 365
- Built-in setup instructions per provider
- Connection test before saving
- Secure credential storage in browser localStorage

---

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment
Edit `.env` and set your SMTP credentials:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
SMTP_FROM_NAME=Your Name
SMTP_FROM_EMAIL=your-email@gmail.com

MAX_EMAILS_PER_DAY=3000
CONCURRENT_EMAILS=3
BATCH_DELAY_MS=1000
```

### 3. Start the server
```bash
npm start
# or for development with auto-reload:
npm run dev
```

### 4. Open the app
```
http://localhost:3000
```

---

## Gmail App Password Setup

Gmail requires an App Password (not your regular password):

1. Enable 2-Step Verification in your Google Account
2. Go to: https://myaccount.google.com/apppasswords
3. Select "Mail" and your device
4. Copy the 16-character password
5. Use that as `SMTP_PASS` in `.env`

---

## Project Structure

```
email-validator/
├── src/
│   ├── server.js          # Express API server
│   ├── emailValidator.js  # Validation engine
│   └── mailer.js          # SMTP & bulk sender
├── public/
│   └── index.html         # Web UI
├── logs/
│   └── activity.log       # Activity log (auto-created)
├── .env                   # Configuration (edit this)
└── package.json
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/validate/single` | Validate one email |
| POST | `/api/validate/bulk` | Validate list (JSON) |
| POST | `/api/validate/upload` | Upload CSV/TXT file |
| GET | `/api/jobs/:id` | Get job status/results |
| GET | `/api/jobs/:id/download` | Download CSV results |
| POST | `/api/smtp/test` | Test SMTP connection |
| GET | `/api/smtp/presets` | Get SMTP presets |
| POST | `/api/email/send-bulk` | Send bulk emails |
| GET | `/api/quota` | Daily quota status |
| GET | `/api/logs` | Activity logs |
| GET | `/api/health` | Health check |

---

## Validation Response Example

```json
{
  "email": "user@example.com",
  "valid": true,
  "score": 90,
  "status": "valid",
  "checks": {
    "syntax": { "passed": true, "reason": "Valid syntax" },
    "domain": {
      "passed": true,
      "reason": "Valid MX records found",
      "mxRecords": [{ "exchange": "mail.example.com", "priority": 10 }]
    },
    "disposable": { "passed": true, "reason": "Not a disposable domain" },
    "roleBased": { "passed": true, "reason": "Not a role-based address" },
    "smtp": { "passed": true, "reason": "SMTP verification passed", "reachable": true }
  },
  "suggestions": [],
  "validatedAt": "2026-06-17T10:30:00.000Z",
  "responseTimeMs": 847
}
```

---

## Deliverability Tips

1. **Warm up your IP** — Start with 50–100 emails/day and ramp up over 2–4 weeks
2. **Set up SPF, DKIM, DMARC** — Critical for inbox delivery
3. **Use a dedicated sending domain** — Don't use your main domain for bulk sends
4. **Clean your list first** — Only send to `valid` status emails (score ≥ 70)
5. **Include unsubscribe links** — Required by CAN-SPAM and GDPR
6. **Monitor bounce rates** — High bounces hurt sender reputation

---

## License
MIT — use freely in commercial or personal projects.
