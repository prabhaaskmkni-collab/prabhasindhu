<?php
ob_start();
/**
 * auth.php — LOCAL TEST MODE (no MySQL needed)
 * ─────────────────────────────────────────────
 * This is a DEVELOPMENT-ONLY version that stores users in a local
 * JSON file (users.json) instead of MySQL.
 *
 * ⚠️  DO NOT UPLOAD THIS FILE TO HOSTINGER.
 *     Upload the real auth.php (auth.php.production) instead.
 * ─────────────────────────────────────────────
 */

define('USERS_FILE', __DIR__ . '/users.json');
define('SESSION_TTL', 7200);

/* ── Bootstrap default users if file doesn't exist ── */
if (!file_exists(USERS_FILE)) {
    $defaults = [
        [
            'id'            => 1,
            'username'      => 'admin',
            // password: Admin@1234
            'password_hash' => password_hash('Admin@1234', PASSWORD_BCRYPT, ['cost' => 12]),
            'role'          => 'admin',
            'created_at'    => date('Y-m-d H:i:s'),
        ],
        [
            'id'            => 2,
            'username'      => 'testuser',
            // password: Test@1234
            'password_hash' => password_hash('Test@1234', PASSWORD_BCRYPT, ['cost' => 12]),
            'role'          => 'user',
            'created_at'    => date('Y-m-d H:i:s'),
        ],
    ];
    file_put_contents(USERS_FILE, json_encode($defaults, JSON_PRETTY_PRINT));
}

/* ── Session bootstrap ── */
if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params(['lifetime' => SESSION_TTL, 'path' => '/']);
    session_start();
}

/* ── Helper: load/save users ── */
function loadUsers(): array {
    return json_decode(file_get_contents(USERS_FILE), true) ?? [];
}
function saveUsers(array $users): void {
    file_put_contents(USERS_FILE, json_encode(array_values($users), JSON_PRETTY_PRINT));
}
function nextId(): int {
    $users = loadUsers();
    return empty($users) ? 1 : (max(array_column($users, 'id')) + 1);
}

/* ── Auth helpers (same API as production auth.php) ── */
function requireAuth(): void {
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TTL) {
        session_unset(); session_destroy();
    }
    if (empty($_SESSION['user_id'])) {
        header('Location: login.php'); exit;
    }
    $_SESSION['last_activity'] = time();
}

function requireAdmin(): void {
    requireAuth();
    if (($_SESSION['role'] ?? '') !== 'admin') {
        http_response_code(403);
        die('<style>body{font-family:monospace;background:#0E0E10;color:#F5F3EE;display:flex;align-items:center;justify-content:center;height:100vh}</style><div style="text-align:center"><h2>403 — Admin only</h2><a href="index.php" style="color:#FF5A1F">← Back</a></div>');
    }
}

function attemptLogin(string $username, string $password): ?array {
    foreach (loadUsers() as $u) {
        if ($u['username'] === trim($username) && password_verify($password, $u['password_hash'])) {
            return $u;
        }
    }
    return null;
}

function startSession(array $user): void {
    session_regenerate_id(true);
    $_SESSION['user_id']       = $user['id'];
    $_SESSION['username']      = $user['username'];
    $_SESSION['role']          = $user['role'];
    $_SESSION['last_activity'] = time();
}

function destroySession(): void {
    session_unset(); session_destroy();
}

function csrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrf(string $token): bool {
    return hash_equals($_SESSION['csrf_token'] ?? '', $token);
}

/* ── Admin CRUD helpers (used by admin.php) ── */
function db_createUser(string $username, string $password, string $role): bool {
    $users = loadUsers();
    foreach ($users as $u) {
        if ($u['username'] === $username) return false; // duplicate
    }
    $users[] = [
        'id'            => nextId(),
        'username'      => $username,
        'password_hash' => password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]),
        'role'          => $role,
        'created_at'    => date('Y-m-d H:i:s'),
    ];
    saveUsers($users);
    return true;
}

function db_deleteUser(int $id): void {
    $users = array_filter(loadUsers(), fn($u) => $u['id'] !== $id);
    saveUsers($users);
}

function db_changePassword(int $id, string $password): void {
    $users = loadUsers();
    foreach ($users as &$u) {
        if ($u['id'] === $id) {
            $u['password_hash'] = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        }
    }
    saveUsers($users);
}

function db_changeRole(int $id, string $role): void {
    $users = loadUsers();
    foreach ($users as &$u) {
        if ($u['id'] === $id) $u['role'] = $role;
    }
    saveUsers($users);
}

function db_getAllUsers(): array {
    return loadUsers();
}

/* ── Banner reminding this is test mode ── */
if (!defined('NO_TEST_BANNER') && php_sapi_name() !== 'cli') {
    // Inject a small banner via output buffering (only for HTML responses)
    ob_start(function($html) {
        $banner = '<div style="position:fixed;bottom:12px;left:50%;transform:translateX(-50%);z-index:99999;background:#7A2C0F;color:#FFCAB0;font-family:monospace;font-size:11px;padding:6px 14px;border-radius:6px;border:1px solid #FF5A1F;pointer-events:none;">⚠ TEST MODE — JSON storage, no MySQL</div>';
        return str_replace('</body>', $banner . '</body>', $html);
    });
}
