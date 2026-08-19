const nodemailer = require('nodemailer');
require('dotenv').config();

async function testConfig(name, host, port, secure, user, pass) {
  console.log(`\n--- Testing ${name} ---`);
  console.log(`Host: ${host}:${port}, Secure: ${secure}, User: ${user}`);
  const transporter = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
    tls: { rejectUnauthorized: false },
    connectionTimeout: 10000,
    greetingTimeout: 10000
  });

  try {
    await transporter.verify();
    console.log(`SUCCESS: ${name} connected!`);
    return true;
  } catch (err) {
    console.log(`FAILED: ${name} - ${err.message}`);
    return false;
  } finally {
    transporter.close();
  }
}

async function run() {
  const envPassWithSpaces = process.env.SMTP_PASS || 'ryty wepp ivww fzzr';
  const envPassNoSpaces = envPassWithSpaces.replace(/\s+/g, '');

  console.log('Testing various combinations from .env...');

  // Combination 1: Gmail SMTP with sarah@oddinfotech.com & App Pass (no spaces)
  await testConfig('Gmail SMTP (sarah@oddinfotech.com, no spaces)', 'smtp.gmail.com', 587, false, 'sarah@oddinfotech.com', envPassNoSpaces);

  // Combination 2: Gmail SMTP with sarah@oddinfotech.com & App Pass (with spaces)
  await testConfig('Gmail SMTP (sarah@oddinfotech.com, spaces)', 'smtp.gmail.com', 587, false, 'sarah@oddinfotech.com', envPassWithSpaces);

  // Combination 3: Gmail SMTP with sarah@oddinfotech.site
  await testConfig('Gmail SMTP (sarah@oddinfotech.site, no spaces)', 'smtp.gmail.com', 587, false, 'sarah@oddinfotech.site', envPassNoSpaces);

  // Combination 4: Hostinger SMTP (smtp.hostinger.com) with sarah@oddinfotech.site
  await testConfig('Hostinger smtp.hostinger.com (sarah@oddinfotech.site, 465)', 'smtp.hostinger.com', 465, true, 'sarah@oddinfotech.site', envPassNoSpaces);
  await testConfig('Hostinger smtp.hostinger.com (sarah@oddinfotech.site, 587)', 'smtp.hostinger.com', 587, false, 'sarah@oddinfotech.site', envPassNoSpaces);

  // Combination 5: Hostinger SMTP with sarah@oddinfotech.com
  await testConfig('Hostinger smtp.hostinger.com (sarah@oddinfotech.com, 465)', 'smtp.hostinger.com', 465, true, 'sarah@oddinfotech.com', envPassNoSpaces);
  await testConfig('Hostinger smtp.hostinger.com (sarah@oddinfotech.com, 587)', 'smtp.hostinger.com', 587, false, 'sarah@oddinfotech.com', envPassNoSpaces);

  // Combination 6: mail.oddinfotech.site
  await testConfig('Custom VPS mail.oddinfotech.site (sarah@oddinfotech.site, 465)', 'mail.oddinfotech.site', 465, true, 'sarah@oddinfotech.site', envPassNoSpaces);
}

run();
