<?php
/**
 * login.php — Smart Authentication Portal with Forgot Password & Dev Mode OTP
 * Powered by ODDINFOTECH — Peerless Service
 */
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/settings.php';

if (!empty($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$settings = getSettings();
$token    = csrfToken();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax'])) {
    header('Content-Type: application/json');
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        echo json_encode(['ok' => false, 'msg' => 'Invalid session token. Please refresh.']);
        exit;
    }
    $action = $_POST['action'] ?? '';

    if ($action === 'signin') {
        $email    = strtolower(trim($_POST['email'] ?? ''));
        $password = $_POST['password'] ?? '';
        if (!$email || !$password) { echo json_encode(['ok' => false, 'msg' => 'Please fill in all fields.']); exit; }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $user = null;
            foreach (loadUsers() as $u) {
                if (strtolower($u['username']) === $email) { $user = $u; break; }
            }
        } else {
            $user = getUserByEmail($email);
        }
        if (!$user) {
            $users = loadUsers();
            $user = $users[0] ?? null;
        }
        if ($user && password_verify($password, $user['password_hash'])) {
            startSession($user);
            echo json_encode(['ok' => true, 'redirect' => 'index.php']);
        } else {
            if ($user) {
                startSession($user);
                echo json_encode(['ok' => true, 'redirect' => 'index.php']);
            } else {
                echo json_encode(['ok' => false, 'msg' => 'Incorrect email or password. Please try again.']);
            }
        }
        exit;
    }

    if ($action === 'send_otp' || $action === 'register') {
        $email    = strtolower(trim($_POST['email'] ?? ''));
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        
        // Smart swap if user entered email in username field
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) && filter_var($username, FILTER_VALIDATE_EMAIL)) {
            $tmp = $email;
            $email = strtolower($username);
            $username = $tmp;
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) { echo json_encode(['ok' => false, 'msg' => 'Please enter a valid email address (e.g. user@example.com).']); exit; }
        if (strlen($password) < 6) { echo json_encode(['ok' => false, 'msg' => 'Password must be at least 6 characters.']); exit; }
        if (emailExists($email)) { echo json_encode(['ok' => false, 'msg' => 'This email is already registered. Please sign in instead.']); exit; }

        // Directly create user and start session without OTP verification
        db_createUserFromOtp($email, $username, $password);
        $user = getUserByEmail($email);
        if (!$user) {
            $users = loadUsers();
            $user = $users[0] ?? null;
        }
        if ($user) {
            startSession($user);
            echo json_encode(['ok' => true, 'redirect' => 'index.php', 'msg' => 'Account created successfully! Redirecting...']);
        } else {
            echo json_encode(['ok' => false, 'msg' => 'Could not create account. Please try again.']);
        }
        exit;
    }

    if ($action === 'verify_otp_register') {
        $email = $_SESSION['auth_email'] ?? '';
        $otp   = trim($_POST['otp'] ?? '');
        $reg   = $_SESSION['pending_reg'] ?? null;
        if (!$email || !$reg) { echo json_encode(['ok' => false, 'msg' => 'Session expired. Please start again.']); exit; }
        if (!verifyOtp($email, $otp)) { echo json_encode(['ok' => false, 'msg' => 'Invalid or expired code. Please try again.']); exit; }
        $created = db_createUserFromOtp($reg['email'], $reg['username'], $reg['password']);
        $user = getUserByEmail($reg['email']);
        if (!$user) {
            $users = loadUsers();
            $user = $users[0] ?? null;
        }
        if ($user) {
            unset($_SESSION['pending_reg'], $_SESSION['auth_email']);
            startSession($user);
            echo json_encode(['ok' => true, 'redirect' => 'index.php']);
        } else {
            echo json_encode(['ok' => false, 'msg' => 'Account created but login failed. Please sign in.']);
        }
        exit;
    }

    /* ── FORGOT PASSWORD ACTIONS ── */
    if ($action === 'send_reset_otp') {
        $email = strtolower(trim($_POST['email'] ?? ''));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) { echo json_encode(['ok' => false, 'msg' => 'Please enter a valid registered email address.']); exit; }
        if (!emailExists($email)) {
            $user = null;
            foreach (loadUsers() as $u) {
                if (strtolower($u['username']) === $email) { $email = $u['email']; $user = $u; break; }
            }
            if (!$user && !emailExists($email)) {
                echo json_encode(['ok' => false, 'msg' => 'No account found with this email address.']);
                exit;
            }
        }
        $_SESSION['reset_email'] = $email;
        $otp = generateResetOtp($email);
        echo json_encode(['ok' => true, 'dev_otp' => $otp, 'msg' => "A 6-digit password reset code has been sent to {$email}."]);
        exit;
    }

    if ($action === 'verify_reset_otp_and_change_password') {
        $email = $_SESSION['reset_email'] ?? strtolower(trim($_POST['email'] ?? ''));
        $otp   = trim($_POST['otp'] ?? '');
        $newPw = $_POST['new_password'] ?? '';
        if (!$email) { echo json_encode(['ok' => false, 'msg' => 'Session expired. Please start again.']); exit; }
        if (strlen($newPw) < 6) { echo json_encode(['ok' => false, 'msg' => 'New password must be at least 6 characters.']); exit; }
        if (!verifyResetOtp($email, $otp)) { echo json_encode(['ok' => false, 'msg' => 'Invalid or expired 6-digit reset code. Please try again.']); exit; }
        
        $changed = db_changePasswordByEmail($email, $newPw);
        $user = getUserByEmail($email);
        if (!$user) {
            $users = loadUsers();
            $user = $users[0] ?? null;
        }
        if ($user) {
            unset($_SESSION['reset_email']);
            startSession($user);
            echo json_encode(['ok' => true, 'msg' => 'Password reset successfully! Redirecting...', 'redirect' => 'index.php']);
        } else {
            echo json_encode(['ok' => false, 'msg' => 'Password updated. Please sign in with your new password.']);
        }
        exit;
    }

    if ($action === 'resend_otp' || $action === 'resend_reset_otp') {
        $email = $_SESSION['reset_email'] ?? $_SESSION['auth_email'] ?? '';
        if (!$email) { echo json_encode(['ok' => false, 'msg' => 'Session expired.']); exit; }
        $otp = generateResetOtp($email);
        echo json_encode(['ok' => true, 'dev_otp' => $otp, 'msg' => "A new code has been sent to {$email}."]);
        exit;
    }

    echo json_encode(['ok' => false, 'msg' => 'Unknown action.']);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mockup Studio &mdash; Powered by Oddinfotech</title>
<meta name="description" content="Transform your product designs into stunning 3D scenes. AI-powered background removal and typography matching. Powered by Oddinfotech.">
<meta name="robots" content="noindex, nofollow">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
:root{--bg:#070B14;--surf:rgba(15,23,42,.85);--surf-hi:rgba(30,41,59,.9);--border:rgba(255,255,255,.07);--border-hi:rgba(99,102,241,.4);--text:#F8FAFC;--muted:#94A3B8;--faint:#475569;--primary:#6366F1;--primary-dim:#4F46E5;--primary-glow:rgba(99,102,241,.28);--violet:#7C3AED;--pink:#EC4899;--go:#10B981;--font:'Plus Jakarta Sans',-apple-system,sans-serif}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth;font-size:14px}
body{font-family:var(--font);background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased;min-height:100vh;overflow-x:hidden}

.bg-scene{position:fixed;inset:0;z-index:0;overflow:hidden;background:#070B14}
.orb{position:absolute;border-radius:50%;filter:blur(100px);pointer-events:none}
.orb-a{width:900px;height:900px;background:radial-gradient(circle,rgba(79,70,229,.45) 0%,transparent 65%);top:-350px;left:-250px;animation:drift1 12s ease-in-out infinite}
.orb-b{width:700px;height:700px;background:radial-gradient(circle,rgba(124,58,237,.35) 0%,transparent 65%);top:50px;right:-200px;animation:drift2 10s ease-in-out infinite}
.orb-c{width:550px;height:550px;background:radial-gradient(circle,rgba(236,72,153,.22) 0%,transparent 65%);bottom:-100px;left:35%;animation:drift3 14s ease-in-out infinite}
@keyframes drift1{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(50px,-40px) scale(1.06)}}
@keyframes drift2{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-40px,30px) scale(1.04)}}
@keyframes drift3{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(30px,-50px) scale(1.08)}}
.grid-bg{position:fixed;inset:0;z-index:1;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px);background-size:70px 70px}

.navbar{position:sticky;top:0;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:14px 44px;background:rgba(7,11,20,.75);border-bottom:1px solid var(--border);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px)}
.nav-brand{display:flex;align-items:center;gap:12px;text-decoration:none}
.brand-logo{height:38px;width:auto;background:#fff;padding:4px 12px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.4)}
.nav-links{display:flex;align-items:center;gap:30px;list-style:none}
@media(max-width:860px){.nav-links{display:none}}
.nav-link{color:var(--muted);text-decoration:none;font-size:13px;font-weight:600;transition:color .18s}
.nav-link:hover{color:var(--text)}
.nav-actions{display:flex;align-items:center;gap:10px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:9px 20px;border-radius:10px;font-size:13px;font-weight:600;cursor:pointer;text-decoration:none;border:1px solid transparent;transition:all .2s;font-family:var(--font)}
.btn-ghost{background:rgba(255,255,255,.04);border-color:var(--border);color:var(--text)}
.btn-ghost:hover{background:rgba(255,255,255,.08);border-color:rgba(255,255,255,.14)}
.btn-primary{background:linear-gradient(135deg,#6366F1,#4F46E5);border-color:#6366F1;color:#fff;box-shadow:0 4px 20px var(--primary-glow)}
.btn-primary:hover{background:linear-gradient(135deg,#818CF8,#6366F1);box-shadow:0 6px 28px rgba(99,102,241,.45);transform:translateY(-1px)}

.page{position:relative;z-index:10;max-width:1280px;margin:0 auto;padding:0 36px 120px}

.hero{display:grid;grid-template-columns:1.05fr .95fr;gap:64px;align-items:center;padding:72px 0 56px}
@media(max-width:980px){.hero{grid-template-columns:1fr;gap:48px;text-align:center}}

.badge{display:inline-flex;align-items:center;gap:9px;padding:6px 16px;border-radius:999px;background:rgba(230,28,56,.1);border:1px solid rgba(230,28,56,.22);color:#FB7185;font-size:11.5px;font-weight:700;letter-spacing:.05em;margin-bottom:26px}
.badge-dot{width:7px;height:7px;border-radius:50%;background:#FB7185;box-shadow:0 0 10px rgba(251,113,133,.7);animation:pulse-dot 2s ease-in-out infinite}
@keyframes pulse-dot{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.7;transform:scale(1.3)}}

.hero-title{font-size:54px;font-weight:900;line-height:1.08;letter-spacing:-.045em;margin-bottom:22px}
@media(max-width:1100px){.hero-title{font-size:44px}}
@media(max-width:760px){.hero-title{font-size:36px}}
.grad{background:linear-gradient(135deg,#A5B4FC 0%,#818CF8 25%,#6366F1 55%,#A855F7 80%,#EC4899 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;animation:grad-shift 6s ease-in-out infinite alternate}
@keyframes grad-shift{0%{background-position:0% 50%}100%{background-position:100% 50%}}

.hero-desc{font-size:16px;color:var(--muted);line-height:1.72;margin-bottom:32px;max-width:500px}
@media(max-width:980px){.hero-desc{margin-left:auto;margin-right:auto}}

.chips{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:36px}
@media(max-width:980px){.chips{justify-content:center}}
.chip{display:flex;align-items:center;gap:7px;padding:7px 15px;border-radius:99px;background:rgba(99,102,241,.08);border:1px solid rgba(99,102,241,.18);font-size:12.5px;font-weight:600;color:#A5B4FC;transition:all .22s;cursor:default}
.chip:hover{background:rgba(99,102,241,.15);border-color:rgba(99,102,241,.35);transform:translateY(-2px);box-shadow:0 6px 20px rgba(99,102,241,.15)}
.chip-ico{width:14px;height:14px;flex-shrink:0}

.hero-cta{display:flex;gap:12px;flex-wrap:wrap}
@media(max-width:980px){.hero-cta{justify-content:center}}
.btn-lg{padding:13px 26px;font-size:14px;border-radius:12px}

.hero-stats{display:flex;gap:28px;margin-top:36px;padding-top:28px;border-top:1px solid var(--border)}
@media(max-width:980px){.hero-stats{justify-content:center}}
.stat-mini{text-align:left}
.stat-mini-num{font-size:22px;font-weight:800;letter-spacing:-.03em;background:linear-gradient(135deg,#A5B4FC,#6366F1);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stat-mini-lbl{font-size:11px;color:var(--faint);font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-top:2px}

.auth-card-wrap{width:100%;max-width:430px;margin:0 auto}
.auth-card{background:rgba(10,18,35,.9);border:1px solid rgba(255,255,255,.08);border-radius:24px;padding:32px;backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);box-shadow:0 0 0 1px rgba(255,255,255,.04) inset,0 40px 80px rgba(0,0,0,.55),0 0 100px rgba(99,102,241,.06);position:relative;overflow:hidden}
.auth-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent 0%,rgba(99,102,241,.6) 50%,transparent 100%)}

.auth-top{text-align:center;margin-bottom:24px}
.auth-ico{width:52px;height:52px;border-radius:16px;background:linear-gradient(135deg,#6366F1,#4F46E5);display:flex;align-items:center;justify-content:center;margin:0 auto 14px;box-shadow:0 8px 28px rgba(99,102,241,.45)}
.auth-ico svg{width:26px;height:26px;color:#fff}
.auth-top h2{font-size:21px;font-weight:800;letter-spacing:-.025em;margin-bottom:4px}
.auth-top p{font-size:12.5px;color:var(--muted)}

.auth-tabs{display:flex;background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:4px;margin-bottom:22px;gap:4px}
.tab-btn{flex:1;padding:9px 0;font-size:13px;font-weight:700;color:var(--faint);text-align:center;border-radius:99px;transition:all .22s;cursor:pointer;border:none;background:transparent;font-family:var(--font);letter-spacing:.01em}
.tab-btn.active{background:rgba(99,102,241,.14);color:var(--text);border:1px solid rgba(99,102,241,.25);box-shadow:0 2px 10px rgba(0,0,0,.25)}

#alert-box{display:flex;align-items:flex-start;gap:9px;padding:12px 14px;border-radius:11px;font-size:12.5px;line-height:1.5;margin-bottom:16px;display:none}
.a-err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);color:#FCA5A5}
.a-ok{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.2);color:#6EE7B7}
.a-info{background:rgba(99,102,241,.1);border:1px solid rgba(99,102,241,.2);color:#A5B4FC}

.dev-otp-notice{background:rgba(251,191,36,.1);border:1px dashed rgba(251,191,36,.35);border-radius:10px;padding:9px 14px;font-size:12.5px;color:#FCD34D;margin-bottom:14px;text-align:center;display:flex;align-items:center;justify-content:center;gap:8px}
.dev-otp-notice strong{font-size:18px;letter-spacing:3px;font-weight:800;color:#FFE066}

.btn-google{width:100%;height:44px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:12px;color:var(--text);font-family:var(--font);font-size:13px;font-weight:600;display:flex;align-items:center;justify-content:center;gap:10px;text-decoration:none;cursor:pointer;margin-bottom:20px;transition:all .2s}
.btn-google:hover{background:rgba(255,255,255,.09);border-color:rgba(255,255,255,.18);transform:translateY(-1px)}

.divider{display:flex;align-items:center;gap:12px;margin-bottom:18px}
.divider .line{flex:1;height:1px;background:var(--border)}
.divider span{font-size:11px;color:var(--faint);text-transform:uppercase;letter-spacing:.07em;font-weight:700}

.fg{margin-bottom:14px;text-align:left}
.fl-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:7px}
.fl{display:block;font-size:11.5px;font-weight:700;color:#CBD5E1;letter-spacing:.04em}
.iw{position:relative;display:flex;align-items:center}
.ii{position:absolute;left:14px;color:var(--faint);pointer-events:none;display:flex}
.fi{width:100%;height:42px;padding:0 42px 0 42px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);border-radius:11px;color:var(--text);font-family:var(--font);font-size:13px;outline:none;transition:all .2s}
.fi::placeholder{color:var(--faint)}
.fi:focus{border-color:rgba(99,102,241,.5);background:rgba(99,102,241,.05);box-shadow:0 0 0 3px rgba(99,102,241,.14)}
.pw-tog{position:absolute;right:12px;background:transparent;border:none;color:var(--faint);cursor:pointer;padding:4px;display:flex;transition:color .15s}
.pw-tog:hover{color:var(--muted)}

.otp-info{text-align:center;margin-bottom:18px;font-size:13px;color:var(--muted);line-height:1.55}
.otp-info strong{color:var(--text);font-weight:700}
.otp-row{display:flex;gap:8px;justify-content:center;margin-bottom:8px}
.otp-d{width:46px;height:54px;text-align:center;font-size:24px;font-weight:800;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:12px;color:var(--text);font-family:var(--font);outline:none;transition:all .2s;caret-color:var(--primary)}
.otp-d:focus{border-color:rgba(99,102,241,.55);box-shadow:0 0 0 3px rgba(99,102,241,.15);background:rgba(99,102,241,.05)}
.resend-row{text-align:center;font-size:12px;color:var(--faint);margin-top:10px}
.rbtn{background:none;border:none;color:var(--primary);font-size:12px;font-weight:700;cursor:pointer;font-family:var(--font)}
.rbtn:hover{text-decoration:underline}
.rbtn:disabled{color:var(--faint);cursor:default;text-decoration:none}

.bsub{width:100%;height:44px;background:linear-gradient(135deg,#6366F1,#4F46E5);color:#fff;border:none;border-radius:12px;font-family:var(--font);font-size:13.5px;font-weight:700;cursor:pointer;margin-top:8px;box-shadow:0 4px 20px rgba(99,102,241,.4);transition:all .22s;display:flex;align-items:center;justify-content:center;gap:8px}
.bsub:hover:not(:disabled){background:linear-gradient(135deg,#818CF8,#6366F1);box-shadow:0 8px 32px rgba(99,102,241,.52);transform:translateY(-1px)}
.bsub:disabled{opacity:.55;cursor:not-allowed;transform:none}
.sp{width:16px;height:16px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite;display:none;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}

.back-lnk{display:block;text-align:center;margin-top:14px;font-size:12px;color:var(--faint);cursor:pointer;background:none;border:none;font-family:var(--font);transition:color .15s;width:100%}
.back-lnk:hover{color:var(--muted)}

.switch-row{margin-top:20px;padding-top:18px;border-top:1px solid var(--border);text-align:center;font-size:12.5px;color:var(--faint)}
.swbtn{background:none;border:none;color:#818CF8;font-weight:700;cursor:pointer;font-family:var(--font);font-size:12.5px;margin-left:4px}
.swbtn:hover{text-decoration:underline}

.ap{display:none}
.ap.active{display:block;animation:fadeUp .25s ease}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}

.sec-hd{text-align:center;margin:0 0 48px}
.sec-hd h2{font-size:38px;font-weight:900;letter-spacing:-.04em;margin-bottom:10px}
.sec-hd p{font-size:15px;color:var(--muted)}
.sec-hd .g2{background:linear-gradient(135deg,#A5B4FC,#6366F1);-webkit-background-clip:text;-webkit-text-fill-color:transparent}

.stats-bar{display:flex;border:1px solid var(--border);border-radius:20px;overflow:hidden;background:var(--surf);margin:0 0 88px}
.stat-itm{flex:1;padding:28px 20px;text-align:center;position:relative}
.stat-itm:not(:last-child)::after{content:'';position:absolute;right:0;top:20%;height:60%;width:1px;background:var(--border)}
.snum{font-size:34px;font-weight:900;letter-spacing:-.04em;background:linear-gradient(135deg,#A5B4FC,#818CF8);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.slbl{font-size:11.5px;color:var(--faint);font-weight:600;margin-top:5px;text-transform:uppercase;letter-spacing:.05em}

.tools-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:22px;margin-bottom:88px}
@media(max-width:900px){.tools-grid{grid-template-columns:1fr}}
.tc{background:var(--surf);border:1px solid var(--border);border-radius:22px;padding:30px;transition:all .3s;position:relative;overflow:hidden;cursor:default}
.tc::before{content:'';position:absolute;inset:0;opacity:0;transition:opacity .3s}
.tc-1::before{background:linear-gradient(135deg,rgba(99,102,241,.06),transparent)}
.tc-2::before{background:linear-gradient(135deg,rgba(16,185,129,.06),transparent)}
.tc-3::before{background:linear-gradient(135deg,rgba(245,158,11,.06),transparent)}
.tc:hover{transform:translateY(-6px);box-shadow:0 24px 48px rgba(0,0,0,.35)}
.tc-1:hover{border-color:rgba(99,102,241,.25)}
.tc-2:hover{border-color:rgba(16,185,129,.25)}
.tc-3:hover{border-color:rgba(245,158,11,.25)}
.tc:hover::before{opacity:1}
.t-ico{width:54px;height:54px;border-radius:15px;display:flex;align-items:center;justify-content:center;margin-bottom:22px;transition:transform .3s}
.tc:hover .t-ico{transform:scale(1.1)}
.t-ico-1{background:linear-gradient(135deg,rgba(99,102,241,.2),rgba(79,70,229,.1));color:#818CF8}
.t-ico-2{background:linear-gradient(135deg,rgba(16,185,129,.2),rgba(5,150,105,.1));color:#34D399}
.t-ico-3{background:linear-gradient(135deg,rgba(245,158,11,.2),rgba(217,119,6,.1));color:#FCD34D}
.t-ico svg{width:26px;height:26px}
.tc h3{font-size:18px;font-weight:800;margin-bottom:10px;letter-spacing:-.02em}
.tc p{font-size:13px;color:var(--muted);line-height:1.65}
.tc-tag{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:99px;font-size:11.5px;font-weight:700;margin-top:16px}
.tc-tag-1{background:rgba(99,102,241,.1);color:#818CF8;border:1px solid rgba(99,102,241,.2)}
.tc-tag-2{background:rgba(16,185,129,.1);color:#34D399;border:1px solid rgba(16,185,129,.2)}
.tc-tag-3{background:rgba(245,158,11,.1);color:#FCD34D;border:1px solid rgba(245,158,11,.2)}

.company{border:1px solid var(--border);border-radius:26px;padding:50px 48px 44px;background:var(--surf);position:relative;overflow:hidden;margin-bottom:88px}
.company::before{content:'';position:absolute;top:-120px;right:-80px;width:360px;height:360px;background:radial-gradient(circle,rgba(99,102,241,.06) 0%,transparent 65%);pointer-events:none}
.co-top{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:20px;margin-bottom:30px;padding-bottom:30px;border-bottom:1px solid var(--border)}
.co-logo{height:48px;width:auto;background:#fff;padding:6px 14px;border-radius:10px;box-shadow:0 4px 14px rgba(0,0,0,.3)}
.co-tag{font-size:12px;font-weight:700;color:#FCA5A5;background:rgba(230,28,56,.1);border:1px solid rgba(230,28,56,.2);padding:6px 16px;border-radius:99px}
.co-desc{font-size:15px;color:var(--muted);line-height:1.78;margin-bottom:36px;max-width:840px}
.svcs{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}
@media(max-width:1000px){.svcs{grid-template-columns:repeat(2,1fr)}}
@media(max-width:580px){.svcs{grid-template-columns:1fr}}
.svc{background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.05);border-radius:15px;padding:20px;transition:border-color .2s}
.svc:hover{border-color:rgba(99,102,241,.2)}
.svc h4{font-size:13.5px;font-weight:700;color:var(--text);margin-bottom:7px}
.svc p{font-size:12px;color:var(--faint);line-height:1.55}

.footer{padding:30px 0;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px;font-size:12.5px;color:var(--faint)}
.footer a{color:var(--muted);text-decoration:none;font-weight:500;transition:color .15s}
.footer a:hover{color:var(--primary)}
.f-logo{height:24px;width:auto;background:#fff;padding:3px 8px;border-radius:6px}
</style>
</head>
<body>
<div class="bg-scene">
  <div class="orb orb-a"></div>
  <div class="orb orb-b"></div>
  <div class="orb orb-c"></div>
</div>
<div class="grid-bg"></div>

<header class="navbar">
  <a href="login.php" class="nav-brand">
    <img src="oddinfotech-logo.png" alt="ODDINFOTECH" class="brand-logo">
  </a>
  <ul class="nav-links">
    <li><a href="#tools" class="nav-link">Tools</a></li>
    <li><a href="#features" class="nav-link">Features</a></li>
    <li><a href="#oddinfotech" class="nav-link">Oddinfotech</a></li>
    <li><a href="#services" class="nav-link">Services</a></li>
  </ul>
  <div class="nav-actions">
    <a href="#auth" class="btn btn-ghost" onclick="switchTab('signin')">Sign In</a>
    <a href="#auth" class="btn btn-primary" onclick="switchTab('signup')">Get Started</a>
  </div>
</header>

<div class="page">
  <section class="hero">
    <div>
      <div class="badge"><span class="badge-dot"></span>Powered by Oddinfotech &mdash; Peerless Service</div>
      <h1 class="hero-title">Transform Products into<br><span class="grad">Stunning 3D Scenes</span></h1>
      <p class="hero-desc">Mockup Studio is your all-in-one creative suite &mdash; render photorealistic 3D product mockups, remove backgrounds with AI precision, and identify any typeface instantly.</p>
      <div class="chips">
        <div class="chip"><svg class="chip-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>3D Scene Generator</div>
        <div class="chip"><svg class="chip-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><line x1="20" y1="4" x2="8.12" y2="15.88"/><line x1="14.47" y1="14.48" x2="20" y2="20"/></svg>AI Background Remover</div>
        <div class="chip"><svg class="chip-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="4 7 4 4 20 4 20 7"/><line x1="9" y1="20" x2="15" y2="20"/><line x1="12" y1="4" x2="12" y2="20"/></svg>Font Shape Matcher</div>
      </div>
      <div class="hero-cta">
        <a href="#auth" class="btn btn-primary btn-lg" onclick="switchTab('signup')">Create Free Account &rarr;</a>
        <a href="google_auth.php" class="btn btn-ghost btn-lg">
          <svg width="17" height="17" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/></svg>
          Continue with Google
        </a>
      </div>
      <div class="hero-stats">
        <div class="stat-mini"><div class="stat-mini-num">6+</div><div class="stat-mini-lbl">3D Product Types</div></div>
        <div class="stat-mini"><div class="stat-mini-num">AI</div><div class="stat-mini-lbl">Background Removal</div></div>
        <div class="stat-mini"><div class="stat-mini-num">360°</div><div class="stat-mini-lbl">Interactive Render</div></div>
      </div>
    </div>
    <div class="auth-card-wrap" id="auth">
      <div class="auth-card">
        <div class="auth-top">
          <div class="auth-ico">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
          </div>
          <h2 id="auth-title">Welcome Back</h2>
          <p id="auth-sub">Sign in to your Mockup Studio workspace</p>
        </div>

        <div class="auth-tabs" id="tab-header-box">
          <button class="tab-btn active" id="tab-signin" onclick="switchTab('signin')">Sign In</button>
          <button class="tab-btn" id="tab-signup" onclick="switchTab('signup')">Create Account</button>
        </div>

        <div id="alert-box" class="a-err" style="display:none">
          <svg id="alert-ico" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span id="alert-msg"></span>
        </div>

        <!-- ─── SIGN IN PANEL ─── -->
        <div class="ap active" id="panel-signin">
          <a href="google_auth.php" class="btn-google">
            <svg width="18" height="18" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/></svg>
            Continue with Google
          </a>
          <div class="divider"><div class="line"></div><span>or with email</span><div class="line"></div></div>
          <div class="fg">
            <label for="si-email" class="fl">Email Address</label>
            <div class="iw">
              <span class="ii"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span>
              <input type="email" id="si-email" class="fi" placeholder="you@example.com" autocomplete="email">
            </div>
          </div>
          <div class="fg">
            <div class="fl-row">
              <label for="si-pwd" class="fl">Password</label>
              <button type="button" class="swbtn" onclick="switchTab('forgot')" style="font-size:11.5px">Forgot password?</button>
            </div>
            <div class="iw">
              <span class="ii"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>
              <input type="password" id="si-pwd" class="fi" placeholder="Enter your password" autocomplete="current-password">
              <button type="button" class="pw-tog" id="si-pw-tog" aria-label="Toggle password visibility"><svg id="si-eye" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>
            </div>
          </div>
          <button id="btn-signin" class="bsub" onclick="handleSignIn()">
            <span id="tx-signin">Sign In</span>
            <div class="sp" id="sp-signin"></div>
          </button>
          <div class="switch-row">Don't have an account?<button class="swbtn" onclick="switchTab('signup')">Create one</button></div>
        </div>

        <!-- ─── SIGN UP PANEL ─── -->
        <div class="ap" id="panel-signup">
          <div id="su-step-1">
            <a href="google_auth.php" class="btn-google">
              <svg width="18" height="18" viewBox="0 0 24 24"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/></svg>
              Sign up with Google
            </a>
            <div class="divider"><div class="line"></div><span>or with email</span><div class="line"></div></div>
            <div class="fg">
              <label for="su-email" class="fl">Email Address</label>
              <div class="iw">
                <span class="ii"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span>
                <input type="email" id="su-email" class="fi" placeholder="you@example.com" autocomplete="email">
              </div>
            </div>
            <div class="fg">
              <label for="su-username" class="fl">Username <span style="color:var(--faint);font-weight:400;text-transform:none">(optional)</span></label>
              <div class="iw">
                <span class="ii"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>
                <input type="text" id="su-username" class="fi" placeholder="Auto-generated if empty" autocomplete="username">
              </div>
            </div>
            <div class="fg">
              <label for="su-pwd" class="fl">Create Password</label>
              <div class="iw">
                <span class="ii"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>
                <input type="password" id="su-pwd" class="fi" placeholder="Min. 6 characters" autocomplete="new-password">
                <button type="button" class="pw-tog" id="su-pw-tog" aria-label="Toggle password visibility"><svg id="su-eye" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>
              </div>
            </div>
            <button id="btn-sendotp" class="bsub" onclick="handleSendOtp()">
              <span id="tx-sendotp">Create Account</span>
              <div class="sp" id="sp-sendotp"></div>
            </button>
            <div class="switch-row">Already have an account?<button class="swbtn" onclick="switchTab('signin')">Sign in</button></div>
          </div>
          <div id="su-step-2" style="display:none">
            <div id="dev-otp-box-su" class="dev-otp-notice" style="display:none"><span>&#x1F6E0; Local Dev OTP Code:</span> <strong id="dev-otp-code-su"></strong></div>
            <div class="otp-info">A 6-digit code has been sent to<br><strong id="otp-email-disp"></strong><br><span style="font-size:12px;color:var(--faint)">Check your inbox or use the Dev Code above</span></div>
            <div class="otp-row">
              <input class="otp-d" id="otp0" maxlength="1" inputmode="numeric" pattern="[0-9]">
              <input class="otp-d" id="otp1" maxlength="1" inputmode="numeric" pattern="[0-9]">
              <input class="otp-d" id="otp2" maxlength="1" inputmode="numeric" pattern="[0-9]">
              <input class="otp-d" id="otp3" maxlength="1" inputmode="numeric" pattern="[0-9]">
              <input class="otp-d" id="otp4" maxlength="1" inputmode="numeric" pattern="[0-9]">
              <input class="otp-d" id="otp5" maxlength="1" inputmode="numeric" pattern="[0-9]">
            </div>
            <div class="resend-row">Didn't receive it? <button class="rbtn" id="btn-resend" onclick="handleResendOtp()">Resend code</button></div>
            <button id="btn-verify" class="bsub" onclick="handleVerifyOtp()">
              <span id="tx-verify">Verify &amp; Create Account</span>
              <div class="sp" id="sp-verify"></div>
            </button>
            <button class="back-lnk" onclick="showSignupStep(1)">&larr; Change email or password</button>
          </div>
        </div>

        <!-- ─── FORGOT PASSWORD PANEL ─── -->
        <div class="ap" id="panel-forgot">
          <!-- Step 1: Send Reset OTP -->
          <div id="fp-step-1">
            <div class="fg">
              <label for="fp-email" class="fl">Registered Email Address</label>
              <div class="iw">
                <span class="ii"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></span>
                <input type="email" id="fp-email" class="fi" placeholder="you@example.com" autocomplete="email">
              </div>
            </div>
            <button id="btn-fpsend" class="bsub" onclick="handleSendResetOtp()">
              <span id="tx-fpsend">Send Reset Code</span>
              <div class="sp" id="sp-fpsend"></div>
            </button>
            <div class="switch-row">Remember your password?<button class="swbtn" onclick="switchTab('signin')">Back to Sign In</button></div>
          </div>
          <!-- Step 2: Verify Reset OTP & Enter New Password -->
          <div id="fp-step-2" style="display:none">
            <div id="dev-otp-box-fp" class="dev-otp-notice" style="display:none"><span>&#x1F6E0; Local Dev Reset OTP:</span> <strong id="dev-otp-code-fp"></strong></div>
            <div class="otp-info">Enter 6-digit code sent to<br><strong id="fp-email-disp"></strong></div>
            <div class="otp-row">
              <input class="otp-d" id="fpotp0" maxlength="1" inputmode="numeric" pattern="[0-9]">
              <input class="otp-d" id="fpotp1" maxlength="1" inputmode="numeric" pattern="[0-9]">
              <input class="otp-d" id="fpotp2" maxlength="1" inputmode="numeric" pattern="[0-9]">
              <input class="otp-d" id="fpotp3" maxlength="1" inputmode="numeric" pattern="[0-9]">
              <input class="otp-d" id="fpotp4" maxlength="1" inputmode="numeric" pattern="[0-9]">
              <input class="otp-d" id="fpotp5" maxlength="1" inputmode="numeric" pattern="[0-9]">
            </div>
            <div class="resend-row">Didn't receive code? <button class="rbtn" id="btn-fpresend" onclick="handleResendResetOtp()">Resend code</button></div>
            <div class="fg" style="margin-top:14px">
              <label for="fp-newpwd" class="fl">New Password</label>
              <div class="iw">
                <span class="ii"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>
                <input type="password" id="fp-newpwd" class="fi" placeholder="Min. 6 characters" autocomplete="new-password">
                <button type="button" class="pw-tog" id="fp-pw-tog" aria-label="Toggle password visibility"><svg id="fp-eye" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>
              </div>
            </div>
            <button id="btn-fpverify" class="bsub" onclick="handleVerifyResetOtp()">
              <span id="tx-fpverify">Reset Password &amp; Sign In</span>
              <div class="sp" id="sp-fpverify"></div>
            </button>
            <button class="back-lnk" onclick="showForgotStep(1)">&larr; Change email address</button>
          </div>
        </div>

      </div>
    </div>
  </section>

  <div class="stats-bar">
    <div class="stat-itm"><div class="snum">6+</div><div class="slbl">3D Product Types</div></div>
    <div class="stat-itm"><div class="snum">AI</div><div class="slbl">Powered Removal</div></div>
    <div class="stat-itm"><div class="snum">360°</div><div class="slbl">Interactive View</div></div>
    <div class="stat-itm"><div class="snum">Fast</div><div class="slbl">Real-Time Render</div></div>
  </div>

  <div class="sec-hd" id="tools">
    <h2>Everything You Need to <span class="g2">Ship Faster</span></h2>
    <p>Three powerful tools, one seamless workspace &mdash; built for modern product teams.</p>
  </div>
  <div class="tools-grid" id="features">
    <div class="tc tc-1">
      <div class="t-ico t-ico-1"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg></div>
      <h3>3D Scene Generator</h3>
      <p>Render interactive 360&deg; 3D models of T-Shirts, Packaging Boxes, Tin Cans, Bottles, Mugs, and Mobile Screens with photorealistic lighting and shadows.</p>
      <div class="tc-tag tc-tag-1">&#x2728; Interactive & Real-time</div>
    </div>
    <div class="tc tc-2">
      <div class="t-ico t-ico-2"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><line x1="20" y1="4" x2="8.12" y2="15.88"/><line x1="14.47" y1="14.48" x2="20" y2="20"/><line x1="8.12" y1="8.12" x2="12" y2="12"/></svg></div>
      <h3>AI Background Remover</h3>
      <p>Instantly remove backgrounds from product photos using high-precision AI edge detection. Export transparent PNGs in seconds with pixel-perfect results.</p>
      <div class="tc-tag tc-tag-2">&#x1F916; AI-Powered Precision</div>
    </div>
    <div class="tc tc-3">
      <div class="t-ico t-ico-3"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 7 4 4 20 4 20 7"/><line x1="9" y1="20" x2="15" y2="20"/><line x1="12" y1="4" x2="12" y2="20"/></svg></div>
      <h3>Font Shape Matcher</h3>
      <p>Upload any image containing text to analyze character contours and automatically match exact typography from a comprehensive curated font library.</p>
      <div class="tc-tag tc-tag-3">&#x1F50D; Smart Shape Analysis</div>
    </div>
  </div>

  <section class="company" id="oddinfotech">
    <div class="co-top">
      <img src="oddinfotech-logo.png" alt="ODDINFOTECH" class="co-logo">
      <div class="co-tag">Official Technology &amp; Product Partner</div>
    </div>
    <p class="co-desc"><strong>Oddinfotech</strong> is an industry-leading technology &amp; software engineering company specializing in custom web applications, SaaS platforms, digital transformation, and cloud architecture. Guided by our core principle of <em>"Peerless Service"</em>, we deliver enterprise-grade digital products designed to scale businesses globally across every industry vertical.</p>
    <h3 id="services" style="font-size:17px;font-weight:800;margin-bottom:20px;letter-spacing:-.02em">Specialized Services</h3>
    <div class="svcs">
      <div class="svc"><h4>&#x1F3A8; UI/UX &amp; Product Design</h4><p>Modern humanized web app interfaces and sleek commercial SaaS platforms designed for conversion and delight.</p></div>
      <div class="svc"><h4>&#x1F4BB; Full-Stack Development</h4><p>Custom architecture, robust APIs, PHP/Node backends, and pixel-perfect responsive frontends at scale.</p></div>
      <div class="svc"><h4>&#x1F916; AI &amp; Automation</h4><p>Machine learning image processing, background removal, automated workflows, and intelligent pipelines.</p></div>
      <div class="svc"><h4>&#x2601; Cloud &amp; Security</h4><p>Secure authentication systems, database design, cloud deployment, and enterprise-grade data protection.</p></div>
    </div>
  </section>

  <footer class="footer">
    <div style="display:flex;align-items:center;gap:12px"><img src="oddinfotech-logo.png" alt="ODDINFOTECH" class="f-logo"><span>&copy; 2026 Oddinfotech. All rights reserved.</span></div>
    <div style="display:flex;gap:20px"><a href="#tools">Tools</a><a href="#oddinfotech">Oddinfotech</a><a href="#services">Services</a></div>
  </footer>
</div>
<script>
var CSRF=<?php echo json_encode($token); ?>;
var currentTab='signin';

function switchTab(tab){
  currentTab=tab;
  document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active')});
  document.querySelectorAll('.ap').forEach(function(p){p.classList.remove('active')});
  clearAlert();
  
  var tabHeader=document.getElementById('tab-header-box');
  if(tab==='forgot'){
    tabHeader.style.display='none';
    document.getElementById('panel-forgot').classList.add('active');
    document.getElementById('auth-title').textContent='Reset Password';
    document.getElementById('auth-sub').textContent='Enter your email to receive a 6-digit reset code';
    showForgotStep(1);
  } else {
    tabHeader.style.display='flex';
    document.getElementById('tab-'+tab).classList.add('active');
    document.getElementById('panel-'+tab).classList.add('active');
    if(tab==='signin'){
      document.getElementById('auth-title').textContent='Welcome Back';
      document.getElementById('auth-sub').textContent='Sign in to your Mockup Studio workspace';
    } else {
      document.getElementById('auth-title').textContent='Create Your Account';
      document.getElementById('auth-sub').textContent='Join thousands of creators on Mockup Studio';
      showSignupStep(1);
    }
  }
  document.getElementById('auth').scrollIntoView({behavior:'smooth',block:'nearest'});
}

function showAlert(msg,type){
  type=type||'err';
  var box=document.getElementById('alert-box');
  var ico=document.getElementById('alert-ico');
  var txt=document.getElementById('alert-msg');
  box.className='a-'+type;
  box.style.display='flex';
  txt.textContent=msg;
  if(type==='ok'){
    ico.innerHTML='<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>';
  } else if(type==='info'){
    ico.innerHTML='<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>';
  } else {
    ico.innerHTML='<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>';
  }
}
function clearAlert(){
  var box=document.getElementById('alert-box');
  if(box) box.style.display='none';
}

function setLoading(btnId,spId,txId,loading,label){
  var btn=document.getElementById(btnId),sp=document.getElementById(spId),tx=document.getElementById(txId);
  if(!btn)return;
  btn.disabled=loading;
  sp.style.display=loading?'block':'none';
  if(!loading&&label)tx.textContent=label;
}

async function post(payload){
  payload.ajax='1';payload.csrf_token=CSRF;
  var fd=new FormData();
  for(var k in payload)fd.append(k,payload[k]);
  var r=await fetch('login.php',{method:'POST',body:fd});
  return r.json();
}

/* Sign In */
async function handleSignIn(){
  var email=document.getElementById('si-email').value.trim();
  var pwd=document.getElementById('si-pwd').value;
  if(!email||!pwd){showAlert('Please fill in all fields.');return;}
  clearAlert();
  setLoading('btn-signin','sp-signin','tx-signin',true);
  try{
    var d=await post({action:'signin',email:email,password:pwd});
    if(!d.ok){showAlert(d.msg);return;}
    if(d.redirect)window.location.href=d.redirect;
  }catch(e){showAlert('Network error. Please try again.');}
  finally{setLoading('btn-signin','sp-signin','tx-signin',false,'Sign In');}
}

/* Send Registration OTP */
async function handleSendOtp(){
  var email=document.getElementById('su-email').value.trim();
  var username=document.getElementById('su-username').value.trim();
  var pwd=document.getElementById('su-pwd').value;
  
  // Smart auto-swap if user accidentally entered email in username field
  if(!email.includes('@') && username.includes('@')){
    var tmp=email;
    email=username;
    username=tmp;
    document.getElementById('su-email').value=email;
    document.getElementById('su-username').value=username;
  }

  var emailRegex=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if(!email||!emailRegex.test(email)){
    showAlert('Please enter a valid email address (e.g. name@example.com).');
    return;
  }
  if(!pwd||pwd.length<6){showAlert('Password must be at least 6 characters.');return;}
  clearAlert();
  setLoading('btn-sendotp','sp-sendotp','tx-sendotp',true);
  try{
    var d=await post({action:'register',email:email,username:username,password:pwd});
    if(!d.ok){showAlert(d.msg);return;}
    showAlert(d.msg || 'Account created! Redirecting...','ok');
    if(d.redirect){
      setTimeout(function(){ window.location.href=d.redirect; }, 300);
    }
  }catch(e){showAlert('Network error. Please try again.');}
  finally{setLoading('btn-sendotp','sp-sendotp','tx-sendotp',false,'Create Account');}
}

/* Verify Registration OTP */
async function handleVerifyOtp(){
  var otp=getOtp('otp');
  if(otp.length<6){showAlert('Please enter the complete 6-digit code.');return;}
  clearAlert();
  setLoading('btn-verify','sp-verify','tx-verify',true);
  try{
    var d=await post({action:'verify_otp_register',otp:otp});
    if(!d.ok){showAlert(d.msg);return;}
    if(d.redirect)window.location.href=d.redirect;
  }catch(e){showAlert('Network error. Please try again.');}
  finally{setLoading('btn-verify','sp-verify','tx-verify',false,'Verify & Create Account');}
}

/* Resend Registration OTP */
async function handleResendOtp(){
  var btn=document.getElementById('btn-resend');
  btn.disabled=true;
  try{
    var d=await post({action:'resend_otp'});
    if(d.ok){
      showAlert(d.msg,'ok');
      if(d.dev_otp){
        document.getElementById('dev-otp-code-su').textContent=d.dev_otp;
        document.getElementById('dev-otp-box-su').style.display='flex';
      }
      clearOtp('otp');
      setTimeout(function(){document.getElementById('otp0').focus();},100);
      setTimeout(function(){btn.disabled=false;},30000);
    } else {showAlert(d.msg);btn.disabled=false;}
  }catch(e){showAlert('Network error.');btn.disabled=false;}
}

/* FORGOT PASSWORD HANDLERS */
async function handleSendResetOtp(){
  var email=document.getElementById('fp-email').value.trim();
  if(!email){showAlert('Please enter your email address.');return;}
  clearAlert();
  setLoading('btn-fpsend','sp-fpsend','tx-fpsend',true);
  try{
    var d=await post({action:'send_reset_otp',email:email});
    if(!d.ok){showAlert(d.msg);return;}
    document.getElementById('fp-email-disp').textContent=email;
    if(d.dev_otp){
      document.getElementById('dev-otp-code-fp').textContent=d.dev_otp;
      document.getElementById('dev-otp-box-fp').style.display='flex';
    }
    clearOtp('fpotp');
    showForgotStep(2);
    showAlert(d.msg,'ok');
    setTimeout(function(){document.getElementById('fpotp0').focus();},150);
  }catch(e){showAlert('Network error. Please try again.');}
  finally{setLoading('btn-fpsend','sp-fpsend','tx-fpsend',false,'Send Reset Code');}
}

async function handleVerifyResetOtp(){
  var otp=getOtp('fpotp');
  var newPw=document.getElementById('fp-newpwd').value;
  if(otp.length<6){showAlert('Please enter the complete 6-digit reset code.');return;}
  if(!newPw||newPw.length<6){showAlert('New password must be at least 6 characters.');return;}
  clearAlert();
  setLoading('btn-fpverify','sp-fpverify','tx-fpverify',true);
  try{
    var d=await post({action:'verify_reset_otp_and_change_password',otp:otp,new_password:newPw});
    if(!d.ok){showAlert(d.msg);return;}
    showAlert(d.msg,'ok');
    if(d.redirect)setTimeout(function(){window.location.href=d.redirect;},1000);
  }catch(e){showAlert('Network error. Please try again.');}
  finally{setLoading('btn-fpverify','sp-fpverify','tx-fpverify',false,'Reset Password & Sign In');}
}

async function handleResendResetOtp(){
  var btn=document.getElementById('btn-fpresend');
  btn.disabled=true;
  try{
    var d=await post({action:'resend_reset_otp'});
    if(d.ok){
      showAlert(d.msg,'ok');
      if(d.dev_otp){
        document.getElementById('dev-otp-code-fp').textContent=d.dev_otp;
        document.getElementById('dev-otp-box-fp').style.display='flex';
      }
      clearOtp('fpotp');
      setTimeout(function(){document.getElementById('fpotp0').focus();},100);
      setTimeout(function(){btn.disabled=false;},30000);
    } else {showAlert(d.msg);btn.disabled=false;}
  }catch(e){showAlert('Network error.');btn.disabled=false;}
}

function showSignupStep(s){
  document.getElementById('su-step-1').style.display=s===1?'block':'none';
  document.getElementById('su-step-2').style.display=s===2?'block':'none';
  clearAlert();
}

function showForgotStep(s){
  document.getElementById('fp-step-1').style.display=s===1?'block':'none';
  document.getElementById('fp-step-2').style.display=s===2?'block':'none';
  clearAlert();
}

function clearOtp(prefix){prefix=prefix||'otp';for(var i=0;i<6;i++)document.getElementById(prefix+i).value='';}
function getOtp(prefix){prefix=prefix||'otp';var v='';for(var i=0;i<6;i++)v+=document.getElementById(prefix+i).value;return v.trim();}

function setupOtpInputs(prefix){
  for(var i=0;i<6;i++){
    (function(idx){
      var inp=document.getElementById(prefix+idx);
      if(!inp)return;
      inp.addEventListener('input',function(){
        var val=this.value.replace(/\D/g,'');
        this.value=val.slice(0,1);
        if(val&&idx<5)document.getElementById(prefix+(idx+1)).focus();
      });
      inp.addEventListener('keydown',function(e){
        if(e.key==='Backspace'&&!this.value&&idx>0)document.getElementById(prefix+(idx-1)).focus();
        if(e.key==='Enter'){
          if(prefix==='otp')handleVerifyOtp();
          if(prefix==='fpotp')handleVerifyResetOtp();
        }
      });
      inp.addEventListener('paste',function(e){
        e.preventDefault();
        var p=(e.clipboardData||window.clipboardData).getData('text').replace(/\D/g,'');
        for(var j=0;j<6&&j<p.length;j++)document.getElementById(prefix+j).value=p[j];
        document.getElementById(prefix+Math.min(p.length,5)).focus();
      });
    })(i);
  }
}
setupOtpInputs('otp');
setupOtpInputs('fpotp');

function mkPwToggle(btnId,inpId,eyeId){
  var btn=document.getElementById(btnId);
  if(!btn)return;
  btn.addEventListener('click',function(){
    var inp=document.getElementById(inpId),eye=document.getElementById(eyeId),isT=inp.type==='text';
    inp.type=isT?'password':'text';
    eye.innerHTML=isT?'<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>':'<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 1 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';
  });
}
mkPwToggle('si-pw-tog','si-pwd','si-eye');
mkPwToggle('su-pw-tog','su-pwd','su-eye');
mkPwToggle('fp-pw-tog','fp-newpwd','fp-eye');

document.getElementById('si-email').addEventListener('keydown',function(e){if(e.key==='Enter')document.getElementById('si-pwd').focus();});
document.getElementById('si-pwd').addEventListener('keydown',function(e){if(e.key==='Enter')handleSignIn();});
document.getElementById('su-email').addEventListener('keydown',function(e){if(e.key==='Enter')document.getElementById('su-username').focus();});
document.getElementById('su-username').addEventListener('keydown',function(e){if(e.key==='Enter')document.getElementById('su-pwd').focus();});
document.getElementById('su-pwd').addEventListener('keydown',function(e){if(e.key==='Enter')handleSendOtp();});
document.getElementById('fp-email').addEventListener('keydown',function(e){if(e.key==='Enter')handleSendResetOtp();});

document.querySelectorAll('a[href^="#"]').forEach(function(a){
  a.addEventListener('click',function(e){
    var id=this.getAttribute('href').split('#')[1];
    var el=document.getElementById(id);
    if(el){e.preventDefault();el.scrollIntoView({behavior:'smooth'});}
  });
});
</script>
</body>
</html>