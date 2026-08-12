<?php
/**
 * google_auth.php — Initiates Google OAuth authentication flow
 */
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/settings.php';

$settings = getSettings();
$clientId = $settings['google_client_id'] ?? '';

$isPlaceholder = empty($clientId) 
    || str_contains($clientId, 'YOUR_GOOGLE_') 
    || str_contains($clientId, 'YOUR_CLIENT_ID');

if (empty($settings['google_oauth_enabled']) || $isPlaceholder) {
    die('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Google OAuth Setup Required</title><meta name="viewport" content="width=device-width, initial-scale=1.0"><link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@500;700;800&display=swap" rel="stylesheet"><style>body{font-family:\'Plus Jakarta Sans\',sans-serif;background:#070B14;color:#F8FAFC;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}.card{background:rgba(15,23,42,.9);border:1px solid rgba(255,255,255,.1);border-radius:20px;padding:36px;max-width:440px;text-align:center;box-shadow:0 20px 50px rgba(0,0,0,.6)}.ico{width:56px;height:56px;background:rgba(99,102,241,.15);border:1px solid rgba(99,102,241,.3);border-radius:16px;display:flex;align-items:center;justify-content:center;margin:0 auto 18px;color:#818CF8}h2{font-size:20px;font-weight:800;margin-bottom:8px}p{font-size:13px;color:#94A3B8;line-height:1.6;margin-bottom:24px}.btn{display:inline-flex;align-items:center;justify-content:center;padding:11px 22px;background:#6366F1;color:#fff;text-decoration:none;border-radius:10px;font-size:13px;font-weight:700;transition:all .2s}.btn:hover{background:#4F46E5}</style></head><body><div class="card"><div class="ico"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div><h2>Google OAuth Setup Required</h2><p>Google Sign-In is currently unconfigured. Please update your <strong>Google Client ID &amp; Client Secret</strong> in <code>settings.json</code> or Admin Settings to enable Google authentication.</p><a href="login.php" class="btn">&larr; Back to Login Page</a></div></body></html>');
}

$clientId     = $settings['google_client_id'];
$redirectUri  = getGoogleCallbackUrl();
$scope        = urlencode('email profile');
$state        = csrfToken(); // CSRF protection

if (!empty($_GET['email'])) {
    $_SESSION['auth_email'] = strtolower(trim($_GET['email']));
}


$googleAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth?"
    . "client_id=" . urlencode($clientId)
    . "&redirect_uri=" . urlencode($redirectUri)
    . "&response_type=code"
    . "&scope=" . $scope
    . "&state=" . urlencode($state)
    . "&prompt=select_account";

header("Location: " . $googleAuthUrl);
exit;
