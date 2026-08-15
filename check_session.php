<?php
/**
 * check_session.php — Returns active session information in JSON format
 */
require_once __DIR__ . '/auth.php';

header('Content-Type: application/json');

if (!empty($_SESSION['user_id'])) {
    echo json_encode([
        'logged_in' => true,
        'username'  => $_SESSION['username'],
        'role'      => $_SESSION['role']
    ]);
} else {
    echo json_encode([
        'logged_in' => false
    ]);
}
exit;
