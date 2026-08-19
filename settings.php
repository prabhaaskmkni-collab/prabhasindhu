<?php
/**
 * settings.php — Application settings manager
 * Manages Auth settings (Public Sign Up, Google OAuth Client ID, Client Secret, Callback URL)
 */

define('SETTINGS_FILE', __DIR__ . '/settings.json');

function getSettings(): array {
    $defaults = [
        'allow_public_signup'  => true,
        'google_oauth_enabled' => true,
        'google_client_id'     => '',
        'google_client_secret' => '',
    ];

    if (file_exists(SETTINGS_FILE)) {
        $json = json_decode(file_get_contents(SETTINGS_FILE), true);
        if (is_array($json)) {
            return array_merge($defaults, $json);
        }
    }
    return $defaults;
}

function updateSettings(array $newSettings): void {
    $current = getSettings();
    $updated = array_merge($current, $newSettings);
    file_put_contents(SETTINGS_FILE, json_encode($updated, JSON_PRETTY_PRINT));
}

function getGoogleCallbackUrl(): string {
    $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
    $host   = $_SERVER['HTTP_HOST'] ?? 'localhost:8080';
    return "{$scheme}://{$host}/google_callback.php";
}
