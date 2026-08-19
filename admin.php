<?php
/**
 * admin.php — User management & Auth settings panel (admin-only)
 * Allows managing user accounts, public signups, and Google OAuth credentials.
 */
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/settings.php';
requireAdmin();

/* ── DB compatibility shim ── */
if (!function_exists('db_createUser')) {
    function db_createUser(string $username, string $password, string $role): bool {
        try {
            $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
            db()->prepare('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)')
               ->execute([$username, $hash, $role]);
            return true;
        } catch (PDOException $e) {
            if ($e->getCode() === '23000') return false;
            throw $e;
        }
    }
    function db_deleteUser(int $id): void {
        db()->prepare('DELETE FROM users WHERE id = ?')->execute([$id]);
    }
    function db_changePassword(int $id, string $password): void {
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        db()->prepare('UPDATE users SET password_hash = ? WHERE id = ?')->execute([$hash, $id]);
    }
    function db_changeRole(int $id, string $role): void {
        db()->prepare('UPDATE users SET role = ? WHERE id = ?')->execute([$role, $id]);
    }
    function db_getAllUsers(): array {
        return db()->query('SELECT id, username, role, created_at FROM users ORDER BY created_at DESC')->fetchAll();
    }
}

/* ─── Handle POST actions ─── */
$message = '';
$msgType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $message = 'Invalid session token. Please refresh.';
        $msgType = 'error';
    } else {
        $action = $_POST['action'] ?? '';

        /* ── Update Auth Settings ── */
        if ($action === 'update_settings') {
            updateSettings([
                'allow_public_signup'  => !empty($_POST['allow_public_signup']),
                'google_oauth_enabled' => !empty($_POST['google_oauth_enabled']),
                'google_client_id'     => trim($_POST['google_client_id'] ?? ''),
                'google_client_secret' => trim($_POST['google_client_secret'] ?? ''),
            ]);
            $message = 'Authentication settings updated successfully.';
            $msgType = 'success';
        }

        /* ── Create user ── */
        elseif ($action === 'create') {
            $newUsername = trim($_POST['new_username'] ?? '');
            $newPassword = $_POST['new_password'] ?? '';
            $newRole     = in_array($_POST['new_role'] ?? '', ['user','admin']) ? $_POST['new_role'] : 'user';

            if (strlen($newUsername) < 3 || strlen($newUsername) > 50) {
                $message = 'Username must be 3–50 characters.';
                $msgType = 'error';
            } elseif (!preg_match('/^[a-zA-Z0-9_.-]+$/', $newUsername)) {
                $message = 'Username may only contain letters, numbers, _, . and -';
                $msgType = 'error';
            } elseif (strlen($newPassword) < 8) {
                $message = 'Password must be at least 8 characters.';
                $msgType = 'error';
            } else {
                if (db_createUser($newUsername, $newPassword, $newRole)) {
                    $message = "User \"{$newUsername}\" created successfully.";
                    $msgType = 'success';
                } else {
                    $message = "Username \"{$newUsername}\" already exists.";
                    $msgType = 'error';
                }
            }
        }

        /* ── Delete user ── */
        elseif ($action === 'delete') {
            $delId = (int)($_POST['user_id'] ?? 0);
            if ($delId === (int)$_SESSION['user_id']) {
                $message = 'You cannot delete your own account.';
                $msgType = 'error';
            } elseif ($delId > 0) {
                db_deleteUser($delId);
                $message = 'User account deleted.';
                $msgType = 'success';
            }
        }

        /* ── Change password ── */
        elseif ($action === 'change_password') {
            $cpId   = (int)($_POST['user_id'] ?? 0);
            $cpPass = $_POST['new_password'] ?? '';
            if (strlen($cpPass) < 8) {
                $message = 'New password must be at least 8 characters.';
                $msgType = 'error';
            } elseif ($cpId > 0) {
                db_changePassword($cpId, $cpPass);
                $message = 'Password updated successfully.';
                $msgType = 'success';
            }
        }

        /* ── Change role ── */
        elseif ($action === 'change_role') {
            $crId   = (int)($_POST['user_id'] ?? 0);
            $crRole = in_array($_POST['new_role'] ?? '', ['user','admin']) ? $_POST['new_role'] : 'user';
            if ($crId === (int)$_SESSION['user_id']) {
                $message = 'You cannot change your own role.';
                $msgType = 'error';
            } elseif ($crId > 0) {
                db_changeRole($crId, $crRole);
                $message = 'User role updated.';
                $msgType = 'success';
            }
        }
    }
}

/* ─── Fetch data ─── */
$users       = db_getAllUsers();
$settings    = getSettings();
$callbackUrl = getGoogleCallbackUrl();
$token       = csrfToken();
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Portal — Mockup Studio</title>
<meta name="robots" content="noindex, nofollow">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg-main:       #0B0F19;
    --card-bg:       rgba(17, 24, 39, 0.75);
    --card-border:   rgba(255, 255, 255, 0.08);
    --text-primary:  #F9FAFB;
    --text-secondary:#9CA3AF;
    --text-muted:    #6B7280;
    --primary:       #6366F1;
    --primary-hover: #4F46E5;
    --primary-light: rgba(99, 102, 241, 0.12);
    --input-bg:      rgba(255, 255, 255, 0.03);
    --input-border:  rgba(255, 255, 255, 0.1);
    --danger:        #EF4444;
    --success:       #10B981;
    --font-sans:     'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { font-size: 14px; }
  body {
    font-family: var(--font-sans);
    background-color: var(--bg-main);
    color: var(--text-primary);
    -webkit-font-smoothing: antialiased;
    min-height: 100vh;
  }

  body::before {
    content: ''; position: fixed; inset: 0;
    background: radial-gradient(circle at 50% -10%, rgba(99, 102, 241, 0.12) 0%, transparent 50%), #0B0F19;
    pointer-events: none; z-index: 0;
  }

  .topbar {
    position: sticky; top: 0; z-index: 10;
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 32px; background: rgba(11, 15, 25, 0.85);
    border-bottom: 1px solid var(--card-border);
    backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
  }
  .topbar-brand {
    display: flex; align-items: center; gap: 10px;
    font-size: 15px; font-weight: 700; letter-spacing: -0.01em; text-decoration: none; color: var(--text-primary);
  }
  .topbar-brand .mark {
    width: 28px; height: 28px; border-radius: 8px;
    background: linear-gradient(135deg, #6366F1 0%, #4F46E5 100%);
    display: flex; align-items: center; justify-content: center;
  }
  .topbar-brand .mark svg { width: 15px; height: 15px; color: #fff; }
  .topbar-actions { display: flex; align-items: center; gap: 12px; }
  .badge-admin {
    font-size: 11px; font-weight: 600; background: var(--primary-light); color: #818CF8;
    border: 1px solid rgba(99,102,241,0.25); border-radius: 6px; padding: 2px 8px;
  }
  .btn-nav {
    display: inline-flex; align-items: center; gap: 6px; padding: 7px 14px; border-radius: 8px;
    font-size: 12.5px; font-weight: 600; cursor: pointer; border: 1px solid var(--input-border);
    text-decoration: none; background: rgba(255,255,255,0.03); color: var(--text-primary);
    transition: all 0.15s ease;
  }
  .btn-nav:hover { border-color: rgba(255,255,255,0.2); background: rgba(255,255,255,0.06); }
  .btn-nav.primary { background: var(--primary); border-color: var(--primary); color: #fff; box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3); }
  .btn-nav.primary:hover { background: var(--primary-hover); }
  .btn-nav.danger { background: rgba(239, 68, 68, 0.1); border-color: rgba(239, 68, 68, 0.25); color: #FCA5A5; }
  .btn-nav.danger:hover { background: rgba(239, 68, 68, 0.2); }

  .container {
    position: relative; z-index: 1; max-width: 960px; margin: 0 auto; padding: 40px 24px 60px;
  }
  .page-header { margin-bottom: 32px; }
  .page-header h1 { font-size: 24px; font-weight: 700; letter-spacing: -0.02em; }
  .page-header p { font-size: 13.5px; color: var(--text-secondary); margin-top: 4px; }

  .alert {
    display: flex; align-items: flex-start; gap: 10px; padding: 12px 16px; border-radius: 10px;
    font-size: 13px; margin-bottom: 24px; animation: alertIn 0.2s ease;
  }
  @keyframes alertIn { from { opacity:0; transform:translateY(-4px); } to { opacity:1; transform:translateY(0); } }
  .alert-error   { background: rgba(239, 68, 68, 0.1);  border: 1px solid rgba(239, 68, 68, 0.25); color: #FCA5A5; }
  .alert-success { background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.25); color: #6EE7B7; }

  .card {
    background: var(--card-bg); border: 1px solid var(--card-border);
    border-radius: 14px; overflow: hidden; margin-bottom: 28px;
    backdrop-filter: blur(12px); box-shadow: inset 0 1px 0 0 rgba(255, 255, 255, 0.05);
  }
  .card-header {
    display: flex; align-items: center; justify-content: space-between; padding: 16px 20px;
    border-bottom: 1px solid var(--card-border);
  }
  .card-title { font-size: 13.5px; font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 8px; }
  .card-body { padding: 20px; }

  /* ── Form Controls ── */
  .form-group label { display: block; font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 6px; }
  .form-group .hint { font-size: 11.5px; color: var(--text-muted); margin-top: 4px; line-height: 1.4; }
  input[type="text"], input[type="password"], select {
    width: 100%; height: 38px; padding: 0 12px; background: var(--input-bg);
    border: 1px solid var(--input-border); border-radius: 8px; color: var(--text-primary);
    font-family: var(--font-sans); font-size: 13px; outline: none; transition: border-color 0.15s ease;
  }
  input[type="text"]:focus, input[type="password"]:focus, select:focus {
    border-color: var(--primary); box-shadow: 0 0 0 3px rgba(99,102,241,0.2);
  }

  /* Checkbox / Switch */
  .switch-row {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 0; border-bottom: 1px solid rgba(255,255,255,0.04);
  }
  .switch-row:last-child { border-bottom: none; }
  .switch-info .title { font-size: 13px; font-weight: 600; color: var(--text-primary); }
  .switch-info .desc  { font-size: 12px; color: var(--text-muted); margin-top: 2px; }

  .toggle-switch {
    position: relative; display: inline-block; width: 44px; height: 24px; flex-shrink: 0;
  }
  .toggle-switch input { opacity: 0; width: 0; height: 0; }
  .slider {
    position: absolute; cursor: pointer; inset: 0; background-color: rgba(255,255,255,0.1);
    transition: .2s; border-radius: 24px; border: 1px solid var(--input-border);
  }
  .slider:before {
    position: absolute; content: ""; height: 18px; width: 18px; left: 2px; bottom: 2px;
    background-color: #9CA3AF; transition: .2s; border-radius: 50%;
  }
  input:checked + .slider { background-color: var(--primary); border-color: var(--primary); }
  input:checked + .slider:before { transform: translateX(20px); background-color: #fff; }

  .code-box {
    background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1);
    border-radius: 8px; padding: 10px 14px; font-family: monospace; font-size: 12px; color: #A5B4FC;
    word-break: break-all; user-select: all; margin-top: 6px;
  }

  .form-row { display: grid; grid-template-columns: 1fr 1fr 140px auto; gap: 12px; align-items: end; }
  @media (max-width: 680px) { .form-row { grid-template-columns: 1fr; } }

  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; }
  th {
    font-size: 11.5px; font-weight: 600; color: var(--text-muted);
    text-transform: uppercase; letter-spacing: 0.04em; text-align: left;
    padding: 12px 18px; border-bottom: 1px solid var(--card-border);
  }
  td { padding: 14px 18px; font-size: 13px; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255,255,255,0.015); }

  .user-avatar {
    width: 32px; height: 32px; border-radius: 8px;
    background: linear-gradient(135deg, #4338CA 0%, #6366F1 100%);
    display: inline-flex; align-items: center; justify-content: center;
    font-size: 12px; font-weight: 700; color: #fff; flex-shrink: 0;
  }
  .user-info { display: flex; align-items: center; gap: 12px; }
  .username { font-weight: 600; color: var(--text-primary); }
  .you-tag {
    font-size: 10px; font-weight: 600; background: rgba(16, 185, 129, 0.15);
    color: #6EE7B7; border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 4px; padding: 1px 6px;
  }
  .role-badge { font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 6px; }
  .role-admin { background: rgba(99, 102, 241, 0.15); color: #A5B4FC; border: 1px solid rgba(99, 102, 241, 0.25); }
  .role-user  { background: rgba(255, 255, 255, 0.05); color: var(--text-secondary); border: 1px solid rgba(255, 255, 255, 0.1); }
  .actions-cell { white-space: nowrap; display: flex; gap: 8px; align-items: center; }

  .modal-overlay {
    display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 100;
    align-items: center; justify-content: center; backdrop-filter: blur(4px);
  }
  .modal-overlay.open { display: flex; }
  .modal {
    background: #111827; border: 1px solid var(--card-border); border-radius: 14px;
    padding: 24px; width: 100%; max-width: 380px; box-shadow: 0 20px 50px rgba(0,0,0,0.7);
    animation: modalIn 0.2s cubic-bezier(0.16,1,0.3,1);
  }
  @keyframes modalIn { from { opacity:0; transform:scale(0.95); } to { opacity:1; transform:scale(1); } }
  .modal h3 { font-size: 16px; font-weight: 700; margin-bottom: 6px; }
  .modal p  { font-size: 13px; color: var(--text-secondary); margin-bottom: 20px; line-height: 1.5; }
  .modal-actions { display: flex; gap: 10px; justify-content: flex-end; }
</style>
</head>
<body>

<!-- Topbar -->
<header class="topbar">
  <a href="index.php" class="topbar-brand">
    <div class="mark">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
    </div>
    Mockup Studio Admin
  </a>
  <div class="topbar-actions">
    <span class="badge-admin">Admin</span>
    <span style="font-size:12.5px;color:var(--text-secondary)"><?= htmlspecialchars($_SESSION['username']) ?></span>
    <a href="index.php" class="btn-nav">← Back to Workspace</a>
    <a href="logout.php" class="btn-nav danger">Sign Out</a>
  </div>
</header>

<div class="container">

  <!-- Header -->
  <div class="page-header">
    <h1>Workspace Management</h1>
    <p>Configure authentication, public registration, and Google OAuth credentials.</p>
  </div>

  <!-- Alert -->
  <?php if ($message): ?>
  <div class="alert alert-<?= $msgType ?>">
    <?php if ($msgType === 'success'): ?>
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
    <?php else: ?>
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
    <?php endif; ?>
    <?= htmlspecialchars($message) ?>
  </div>
  <?php endif; ?>

  <!-- Authentication & OAuth Settings Card -->
  <div class="card">
    <div class="card-header">
      <span class="card-title">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        Authentication & Registration Settings
      </span>
    </div>
    <div class="card-body">
      <form method="POST" action="admin.php">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($token) ?>">
        <input type="hidden" name="action" value="update_settings">

        <!-- Switch 1: Public Signup -->
        <div class="switch-row">
          <div class="switch-info">
            <div class="title">Public Self-Registration (Sign Up)</div>
            <div class="desc">Allow new visitors to register an account from the login page.</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" name="allow_public_signup" value="1" <?= !empty($settings['allow_public_signup']) ? 'checked' : '' ?>>
            <span class="slider"></span>
          </label>
        </div>

        <!-- Switch 2: Google OAuth -->
        <div class="switch-row" style="margin-bottom:20px;">
          <div class="switch-info">
            <div class="title">Google OAuth Login</div>
            <div class="desc">Enable "Continue with Google" single sign-on for users.</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" name="google_oauth_enabled" value="1" <?= !empty($settings['google_oauth_enabled']) ? 'checked' : '' ?>>
            <span class="slider"></span>
          </label>
        </div>

        <!-- Google OAuth Inputs -->
        <div style="border-top:1px solid rgba(255,255,255,0.06); padding-top:18px;">
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px;">
            <div class="form-group">
              <label>Google Client ID</label>
              <input type="text" name="google_client_id" value="<?= htmlspecialchars($settings['google_client_id'] ?? '') ?>" placeholder="e.g. 123456789-abc.apps.googleusercontent.com">
            </div>
            <div class="form-group">
              <label>Google Client Secret</label>
              <input type="password" name="google_client_secret" value="<?= htmlspecialchars($settings['google_client_secret'] ?? '') ?>" placeholder="GOCSPX-...">
            </div>
          </div>

          <div class="form-group">
            <label>Google OAuth Authorized Redirect Callback URL (Copy this to Google Console)</label>
            <div class="code-box"><?= htmlspecialchars($callbackUrl) ?></div>
            <div class="hint">Paste this exact URL into your Google Cloud Console under <b>Authorized Redirect URIs</b>.</div>
          </div>
        </div>

        <div style="margin-top:20px; display:flex; justify-content:flex-end;">
          <button type="submit" class="btn-nav primary">Save Authentication Settings</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Add Member Card -->
  <div class="card">
    <div class="card-header">
      <span class="card-title">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="17" y1="11" x2="23" y2="11"/></svg>
        Manually Add New Member
      </span>
    </div>
    <div class="card-body">
      <form method="POST" action="admin.php">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($token) ?>">
        <input type="hidden" name="action" value="create">
        <div class="form-row">
          <div class="form-group">
            <label>Username</label>
            <input type="text" name="new_username" placeholder="e.g. alex" maxlength="50" required>
          </div>
          <div class="form-group">
            <label>Password</label>
            <input type="password" name="new_password" placeholder="Min. 8 characters" required>
          </div>
          <div class="form-group">
            <label>Role</label>
            <select name="new_role">
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div class="form-group">
            <label style="opacity:0">Action</label>
            <button type="submit" class="btn-nav primary" style="height:38px; width:100%; justify-content:center;">
              Create Member
            </button>
          </div>
        </div>
      </form>
    </div>
  </div>

  <!-- Users Table Card -->
  <div class="card">
    <div class="card-header">
      <span class="card-title">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
        Workspace Members (<?= count($users) ?>)
      </span>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Member</th>
            <th>Role</th>
            <th>Joined</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($users as $u): ?>
          <tr>
            <td>
              <div class="user-info">
                <div class="user-avatar"><?= strtoupper(substr($u['username'], 0, 1)) ?></div>
                <span class="username"><?= htmlspecialchars($u['username']) ?></span>
                <?php if ($u['id'] == $_SESSION['user_id']): ?>
                  <span class="you-tag">You</span>
                <?php endif; ?>
              </div>
            </td>
            <td>
              <span class="role-badge role-<?= $u['role'] ?>"><?= ucfirst($u['role']) ?></span>
            </td>
            <td style="color:var(--text-muted); font-size:12.5px;">
              <?= date('M j, Y', strtotime($u['created_at'])) ?>
            </td>
            <td class="actions-cell">
              <button class="btn-nav" onclick="openChangePassword(<?= $u['id'] ?>, '<?= htmlspecialchars($u['username'], ENT_QUOTES) ?>')">
                Change Password
              </button>
              <?php if ($u['id'] != $_SESSION['user_id']): ?>
              <form method="POST" style="display:inline;">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($token) ?>">
                <input type="hidden" name="action" value="change_role">
                <input type="hidden" name="user_id" value="<?= $u['id'] ?>">
                <button type="submit" name="new_role" value="<?= $u['role'] === 'admin' ? 'user' : 'admin' ?>" class="btn-nav">
                  <?= $u['role'] === 'admin' ? 'Set as User' : 'Set as Admin' ?>
                </button>
              </form>
              <button class="btn-nav danger" onclick="openDelete(<?= $u['id'] ?>, '<?= htmlspecialchars($u['username'], ENT_QUOTES) ?>')">
                Delete
              </button>
              <?php endif; ?>
            </td>
          </tr>
          <?php endforeach; ?>
          <?php if (empty($users)): ?>
          <tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:28px;">No members found.</td></tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>

</div>

<!-- Change Password Modal -->
<div class="modal-overlay" id="pwModal">
  <div class="modal">
    <h3>Change Password</h3>
    <p>Set a new password for <strong id="pwModalUsername"></strong>.</p>
    <form method="POST" action="admin.php">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($token) ?>">
      <input type="hidden" name="action" value="change_password">
      <input type="hidden" name="user_id" id="pwModalUserId">
      <div class="form-group" style="margin-bottom:16px;">
        <label>New Password</label>
        <input type="password" name="new_password" id="pwModalInput" placeholder="Min. 8 characters" required>
      </div>
      <div class="modal-actions">
        <button type="button" class="btn-nav" onclick="closeModal('pwModal')">Cancel</button>
        <button type="submit" class="btn-nav primary">Update Password</button>
      </div>
    </form>
  </div>
</div>

<!-- Delete Confirm Modal -->
<div class="modal-overlay" id="delModal">
  <div class="modal">
    <h3>Delete User</h3>
    <p>Are you sure you want to delete <strong id="delModalUsername"></strong>? This action cannot be undone.</p>
    <form method="POST" action="admin.php">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($token) ?>">
      <input type="hidden" name="action" value="delete">
      <input type="hidden" name="user_id" id="delModalUserId">
      <div class="modal-actions">
        <button type="button" class="btn-nav" onclick="closeModal('delModal')">Cancel</button>
        <button type="submit" class="btn-nav danger">Confirm Delete</button>
      </div>
    </form>
  </div>
</div>

<script>
  function openChangePassword(id, username) {
    document.getElementById('pwModalUserId').value   = id;
    document.getElementById('pwModalUsername').textContent = username;
    document.getElementById('pwModalInput').value    = '';
    document.getElementById('pwModal').classList.add('open');
    setTimeout(() => document.getElementById('pwModalInput').focus(), 100);
  }
  function openDelete(id, username) {
    document.getElementById('delModalUserId').value   = id;
    document.getElementById('delModalUsername').textContent = username;
    document.getElementById('delModal').classList.add('open');
  }
  function closeModal(id) {
    document.getElementById(id).classList.remove('open');
  }
  document.querySelectorAll('.modal-overlay').forEach(ov => {
    ov.addEventListener('click', e => { if (e.target === ov) ov.classList.remove('open'); });
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') document.querySelectorAll('.modal-overlay.open').forEach(m => m.classList.remove('open'));
  });
</script>

</body>
</html>
