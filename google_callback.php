<?php
/**
 * google_callback.php — Handles Google OAuth callback redirect
 * Supports both cURL and native PHP stream context (file_get_contents).
 */
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/settings.php';

/* ── HTTP Request Helpers (cURL + Stream Context Fallback) ── */
function httpPostRequest(string $url, array $params): ?string {
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query($params),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_TIMEOUT        => 10,
        ]);
        $res = curl_exec($ch);
        curl_close($ch);
        if ($res !== false && !empty($res)) return $res;
    }

    $opts = [
        'http' => [
            'method'  => 'POST',
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
            'content' => http_build_query($params),
            'ignore_errors' => true,
            'timeout' => 10,
        ],
        'ssl' => [
            'verify_peer'      => false,
            'verify_peer_name' => false,
        ]
    ];
    $context = stream_context_create($opts);
    $res = @file_get_contents($url, false, $context);
    return ($res !== false && !empty($res)) ? $res : null;
}

function httpGetRequest(string $url, string $bearerToken): ?string {
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_HTTPHEADER     => ["Authorization: Bearer {$bearerToken}"],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_TIMEOUT        => 10,
        ]);
        $res = curl_exec($ch);
        curl_close($ch);
        if ($res !== false && !empty($res)) return $res;
    }

    $opts = [
        'http' => [
            'method' => 'GET',
            'header' => "Authorization: Bearer {$bearerToken}\r\n",
            'ignore_errors' => true,
            'timeout' => 10,
        ],
        'ssl' => [
            'verify_peer'      => false,
            'verify_peer_name' => false,
        ]
    ];
    $context = stream_context_create($opts);
    $res = @file_get_contents($url, false, $context);
    return ($res !== false && !empty($res)) ? $res : null;
}

/* ── OAuth Flow ── */
$settings = getSettings();
$code     = $_GET['code']  ?? '';
$state    = $_GET['state'] ?? '';

if (empty($code) || !verifyCsrf($state)) {
    header('Location: login.php?error=' . urlencode('Google authentication failed or session expired.'));
    exit;
}

$clientId     = $settings['google_client_id'];
$clientSecret = $settings['google_client_secret'];
$redirectUri  = getGoogleCallbackUrl();

/* ── 1. Exchange code for access token ── */
$tokenUrl  = 'https://oauth2.googleapis.com/token';
$postFields = [
    'code'          => $code,
    'client_id'     => $clientId,
    'client_secret' => $clientSecret,
    'redirect_uri'  => $redirectUri,
    'grant_type'    => 'authorization_code',
];

$response  = httpPostRequest($tokenUrl, $postFields);
$tokenData = json_decode($response ?? '', true);

if (empty($tokenData['access_token'])) {
    $err = $tokenData['error_description'] 
        ?? $tokenData['error'] 
        ?? (is_string($response) ? substr(strip_tags($response), 0, 150) : 'Empty response from Google Token API.');
    header('Location: login.php?error=' . urlencode('Google OAuth Error: ' . $err));
    exit;
}

/* ── 2. Fetch user profile ── */
$userInfoUrl  = 'https://www.googleapis.com/oauth2/v2/userinfo';
$userInfoJson = httpGetRequest($userInfoUrl, $tokenData['access_token']);
$googleUser   = json_decode($userInfoJson ?? '', true);

if (empty($googleUser['email'])) {
    header('Location: login.php?error=' . urlencode('Failed to retrieve user profile from Google.'));
    exit;
}

$email    = $googleUser['email'];
$username = strtolower(explode('@', $email)[0]);
$username = preg_replace('/[^a-z0-9_.-]/', '', $username);

/* ── 3. Find or create user session ── */
$allUsers = function_exists('db_getAllUsers') ? db_getAllUsers() : db()->query('SELECT id, username, role FROM users')->fetchAll();
$userToLogin = null;

foreach ($allUsers as $u) {
    if ($u['username'] === $username) {
        $userToLogin = $u;
        break;
    }
}

if (!$userToLogin) {
    // Auto-register new Google user
    $randomPassword = bin2hex(random_bytes(16));
    if (function_exists('db_createUser')) {
        db_createUser($username, $randomPassword, 'user');
    } else {
        $hash = password_hash($randomPassword, PASSWORD_BCRYPT);
        db()->prepare('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)')
            ->execute([$username, $hash, 'user']);
    }

    $allUsers = function_exists('db_getAllUsers') ? db_getAllUsers() : db()->query('SELECT id, username, role FROM users')->fetchAll();
    foreach ($allUsers as $u) {
        if ($u['username'] === $username) {
            $userToLogin = $u;
            break;
        }
    }
}

if ($userToLogin) {
    startSession($userToLogin);
    header('Location: index.php');
    exit;
} else {
    header('Location: login.php?error=' . urlencode('Failed to create account.'));
    exit;
}
