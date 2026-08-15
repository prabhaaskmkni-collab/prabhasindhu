<?php
/**
 * logout.php — Destroys the user session and redirects to login
 */
require_once __DIR__ . '/auth.php';

destroySession();

header('Location: login.php');
exit;
