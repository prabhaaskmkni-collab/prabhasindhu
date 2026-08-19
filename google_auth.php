<?php
/**
 * google_auth.php — Initiates Google OAuth authentication flow
 */
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/settings.php';

$settings = getSettings();

if (empty($settings['google_oauth_enabled']) || empty($settings['google_client_id'])) {
    die('<style>body{font-family:sans-serif;background:#0B0F19;color:#F9FAFB;display:flex;align-items:center;justify-content:center;height:100vh}</style><div style="text-align:center"><h2>Google OAuth is disabled</h2><p style="color:#9CA3AF">Please configure Google Client ID in Admin Portal.</p><br><a href="login.php" style="color:#6366F1">← Back to Login</a></div>');
}

$clientId     = $settings['google_client_id'];
$redirectUri  = getGoogleCallbackUrl();
$scope        = urlencode('email profile');
$state        = csrfToken(); // CSRF protection

$googleAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth?"
    . "client_id=" . urlencode($clientId)
    . "&redirect_uri=" . urlencode($redirectUri)
    . "&response_type=code"
    . "&scope=" . $scope
    . "&state=" . urlencode($state)
    . "&prompt=select_account";

header("Location: " . $googleAuthUrl);
exit;
