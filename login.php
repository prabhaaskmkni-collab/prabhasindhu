<?php
/**
 * login.php — Authentication portal for Mockup Studio
 * Supports Sign In, Sign Up (if enabled in settings), and Google OAuth.
 */
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/settings.php';

// Already logged in → go straight to app
if (!empty($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$settings = getSettings();
$error    = $_GET['error'] ?? '';
$success  = $_GET['success'] ?? '';
$mode     = $_GET['mode'] ?? 'signin'; // 'signin' or 'signup'

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid session token. Please refresh the page and try again.';
    } else {
        $action = $_POST['action'] ?? 'signin';

        /* ── Handle Sign In ── */
        if ($action === 'signin') {
            $username = trim($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';

            if ($username === '' || $password === '') {
                $error = 'Please fill in both your username and password.';
            } else {
                $user = attemptLogin($username, $password);
                if ($user) {
                    startSession($user);
                    header('Location: index.php');
                    exit;
                } else {
                    usleep(250000);
                    $error = 'Invalid credentials. Please check your username and password.';
                }
            }
        }

        /* ── Handle Public Sign Up ── */
        elseif ($action === 'signup') {
            $mode = 'signup';
            if (empty($settings['allow_public_signup'])) {
                $error = 'Public account registration is currently disabled.';
            } else {
                $newUsername = trim($_POST['username'] ?? '');
                $newPassword = $_POST['password'] ?? '';

                if (strlen($newUsername) < 3 || strlen($newUsername) > 50) {
                    $error = 'Username must be 3–50 characters.';
                } elseif (!preg_match('/^[a-zA-Z0-9_.-]+$/', $newUsername)) {
                    $error = 'Username can only contain letters, numbers, _, . and -';
                } elseif (strlen($newPassword) < 8) {
                    $error = 'Password must be at least 8 characters.';
                } else {
                    // Create user
                    $created = false;
                    if (function_exists('db_createUser')) {
                        $created = db_createUser($newUsername, $newPassword, 'user');
                    } else {
                        try {
                            $hash = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 12]);
                            db()->prepare('INSERT INTO users (username, password_hash, role) VALUES (?,?,?)')
                                ->execute([$newUsername, $hash, 'user']);
                            $created = true;
                        } catch (PDOException $e) {
                            $created = false;
                        }
                    }

                    if ($created) {
                        // Log user in immediately after signup
                        $user = attemptLogin($newUsername, $newPassword);
                        if ($user) {
                            startSession($user);
                            header('Location: index.php');
                            exit;
                        }
                        $success = 'Account created successfully! You can now sign in.';
                        $mode = 'signin';
                    } else {
                        $error = 'Username "' . htmlspecialchars($newUsername) . '" is already taken.';
                    }
                }
            }
        }
    }
}

$token = csrfToken();
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= $mode === 'signup' ? 'Create Account' : 'Sign In' ?> — Mockup Studio</title>
<meta name="description" content="Sign in or register for your Mockup Studio workspace.">
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

  html, body {
    height: 100%;
    font-family: var(--font-sans);
    background-color: var(--bg-main);
    color: var(--text-primary);
    -webkit-font-smoothing: antialiased;
    overflow: hidden;
  }

  .bg-ambient {
    position: fixed; inset: 0;
    background: 
      radial-gradient(circle at 50% -10%, rgba(99, 102, 241, 0.14) 0%, transparent 50%),
      radial-gradient(circle at 85% 90%, rgba(79, 70, 229, 0.08) 0%, transparent 45%),
      #0B0F19;
    z-index: 0; pointer-events: none;
  }

  .viewport {
    position: relative; z-index: 1; min-height: 100vh;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    padding: 24px 16px;
  }

  .auth-card {
    width: 100%; max-width: 410px;
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 18px;
    padding: 36px 32px;
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    box-shadow: 
      inset 0 1px 0 0 rgba(255, 255, 255, 0.08),
      0 20px 40px -15px rgba(0, 0, 0, 0.6);
    animation: fadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1);
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(12px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .brand-header {
    display: flex; flex-direction: column; align-items: center; text-align: center; margin-bottom: 24px;
  }

  .brand-logo {
    width: 44px; height: 44px;
    background: linear-gradient(135deg, #6366F1 0%, #4F46E5 100%);
    border-radius: 12px; display: flex; align-items: center; justify-content: center;
    margin-bottom: 14px; box-shadow: 0 8px 20px -4px rgba(99, 102, 241, 0.4);
  }

  .brand-logo svg { width: 24px; height: 24px; color: #FFFFFF; }
  .brand-header h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.02em; margin-bottom: 4px; }
  .brand-header p { font-size: 13px; color: var(--text-secondary); line-height: 1.4; }

  /* ── Tab Switcher (Sign In / Sign Up) ── */
  .auth-tabs {
    display: flex; background: rgba(0, 0, 0, 0.25);
    border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 10px;
    padding: 3px; margin-bottom: 22px;
  }

  .tab-btn {
    flex: 1; padding: 7px 0; font-size: 12.5px; font-weight: 600;
    color: var(--text-muted); text-align: center; text-decoration: none;
    border-radius: 8px; transition: all 0.15s ease; cursor: pointer; border: none; background: transparent;
  }

  .tab-btn.active {
    background: rgba(255, 255, 255, 0.08); color: var(--text-primary);
    box-shadow: 0 1px 3px rgba(0,0,0,0.3);
  }

  /* ── Google OAuth Button ── */
  .btn-google {
    width: 100%; height: 40px;
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 10px; color: var(--text-primary);
    font-family: var(--font-sans); font-size: 13px; font-weight: 600;
    display: flex; align-items: center; justify-content: center; gap: 10px;
    text-decoration: none; cursor: pointer; margin-bottom: 20px;
    transition: all 0.15s ease;
  }

  .btn-google:hover {
    background: rgba(255, 255, 255, 0.1); border-color: rgba(255, 255, 255, 0.2);
  }

  .divider-row {
    display: flex; align-items: center; gap: 12px; margin-bottom: 20px;
  }
  .divider-row .line { flex: 1; height: 1px; background: rgba(255, 255, 255, 0.08); }
  .divider-row span { font-size: 11.5px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }

  /* ── Form Controls ── */
  .form-group { margin-bottom: 16px; }
  .form-label { display: block; font-size: 12.5px; font-weight: 600; color: #D1D5DB; margin-bottom: 6px; }
  .input-wrapper { position: relative; display: flex; align-items: center; }
  .input-icon { position: absolute; left: 13px; color: var(--text-muted); pointer-events: none; display: flex; }
  .form-input {
    width: 100%; height: 40px; padding: 0 40px 0 38px;
    background: var(--input-bg); border: 1px solid var(--input-border);
    border-radius: 10px; color: var(--text-primary); font-family: var(--font-sans); font-size: 13px;
    outline: none; transition: all 0.15s ease;
  }
  .form-input::placeholder { color: var(--text-muted); }
  .form-input:hover { border-color: rgba(255, 255, 255, 0.18); }
  .form-input:focus { border-color: var(--primary); background: rgba(99, 102, 241, 0.04); box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2); }

  .toggle-pw-btn {
    position: absolute; right: 12px; background: transparent; border: none;
    color: var(--text-muted); cursor: pointer; padding: 4px; display: flex; border-radius: 6px;
  }
  .toggle-pw-btn:hover { color: var(--text-secondary); }

  .alert {
    display: flex; align-items: flex-start; gap: 10px; padding: 11px 14px;
    border-radius: 10px; font-size: 12.5px; line-height: 1.4; margin-bottom: 18px;
    animation: alertSlide 0.2s ease-out;
  }
  @keyframes alertSlide { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
  .alert-error   { background: rgba(239, 68, 68, 0.1);  border: 1px solid rgba(239, 68, 68, 0.25); color: #FCA5A5; }
  .alert-success { background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.25); color: #6EE7B7; }
  .alert svg { flex-shrink: 0; margin-top: 1px; }

  .btn-submit {
    width: 100%; height: 42px;
    background: linear-gradient(180deg, #6366F1 0%, #4F46E5 100%);
    color: #FFFFFF; border: none; border-radius: 10px;
    font-family: var(--font-sans); font-size: 13.5px; font-weight: 600;
    cursor: pointer; margin-top: 6px; box-shadow: 0 4px 12px rgba(79, 70, 229, 0.35);
    transition: all 0.15s ease; display: flex; align-items: center; justify-content: center;
  }
  .btn-submit:hover { background: linear-gradient(180deg, #6D70F2 0%, #4338CA 100%); box-shadow: 0 6px 16px rgba(79, 70, 229, 0.45); }
  .btn-submit:active { transform: translateY(1px); }

  .card-footer {
    margin-top: 22px; padding-top: 18px; border-top: 1px solid rgba(255, 255, 255, 0.06);
    display: flex; align-items: center; justify-content: space-between; font-size: 12px;
  }
  .footer-text { color: var(--text-muted); }
  .footer-link { color: var(--text-secondary); text-decoration: none; font-weight: 500; }
  .footer-link:hover { color: var(--primary); }
</style>
</head>
<body>

<div class="bg-ambient"></div>

<div class="viewport">
  <div class="auth-card">

    <!-- Header -->
    <div class="brand-header">
      <div class="brand-logo">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polygon points="12 2 2 7 12 12 22 7 12 2"/>
          <polyline points="2 17 12 22 22 17"/>
          <polyline points="2 12 12 17 22 12"/>
        </svg>
      </div>
      <h1>Mockup Studio</h1>
      <p><?= $mode === 'signup' ? 'Create your workspace account' : 'Sign in to your workspace' ?></p>
    </div>

    <!-- Tabs if public signup enabled -->
    <?php if (!empty($settings['allow_public_signup'])): ?>
    <div class="auth-tabs">
      <a href="login.php?mode=signin" class="tab-btn <?= $mode === 'signin' ? 'active' : '' ?>">Sign In</a>
      <a href="login.php?mode=signup" class="tab-btn <?= $mode === 'signup' ? 'active' : '' ?>">Create Account</a>
    </div>
    <?php endif; ?>

    <!-- Alert Messages -->
    <?php if ($error): ?>
    <div class="alert alert-error" role="alert">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
      <span><?= htmlspecialchars($error) ?></span>
    </div>
    <?php endif; ?>
    <?php if ($success): ?>
    <div class="alert alert-success" role="alert">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
      <span><?= htmlspecialchars($success) ?></span>
    </div>
    <?php endif; ?>



    <!-- Form -->
    <form method="POST" action="login.php?mode=<?= $mode ?>" id="authForm">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($token) ?>">
      <input type="hidden" name="action" value="<?= $mode ?>">

      <div class="form-group">
        <label for="username" class="form-label">Username</label>
        <div class="input-wrapper">
          <span class="input-icon">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          </span>
          <input
            type="text"
            id="username"
            name="username"
            class="form-input"
            placeholder="Choose or enter username"
            value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
            autocomplete="username"
            autofocus
            required
          >
        </div>
      </div>

      <div class="form-group">
        <label for="password" class="form-label">Password</label>
        <div class="input-wrapper">
          <span class="input-icon">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </span>
          <input
            type="password"
            id="password"
            name="password"
            class="form-input"
            placeholder="<?= $mode === 'signup' ? 'Min. 8 characters' : 'Enter password' ?>"
            autocomplete="<?= $mode === 'signup' ? 'new-password' : 'current-password' ?>"
            required
          >
          <button type="button" class="toggle-pw-btn" id="togglePw" aria-label="Toggle password visibility">
            <svg id="eyeIcon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
            </svg>
          </button>
        </div>
      </div>

      <button type="submit" class="btn-submit" id="submitBtn">
        <span class="btn-text"><?= $mode === 'signup' ? 'Create Account' : 'Sign In' ?></span>
      </button>
    </form>

    <!-- Footer -->
    <div class="card-footer">
      <span class="footer-text">
        <?= $mode === 'signup' ? 'Already have an account?' : 'Need admin access?' ?>
      </span>
      <?php if ($mode === 'signup'): ?>
        <a href="login.php?mode=signin" class="footer-link">Sign In →</a>
      <?php else: ?>
        <a href="admin.php" class="footer-link">Admin Portal →</a>
      <?php endif; ?>
    </div>

  </div>
</div>

<script>
  const togglePw = document.getElementById('togglePw');
  const pwInput  = document.getElementById('password');
  const eyeIcon  = document.getElementById('eyeIcon');

  const eyeOn  = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
  const eyeOff = `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>`;

  togglePw.addEventListener('click', () => {
    const isPw = pwInput.type === 'password';
    pwInput.type = isPw ? 'text' : 'password';
    eyeIcon.innerHTML = isPw ? eyeOff : eyeOn;
  });
</script>

</body>
</html>
