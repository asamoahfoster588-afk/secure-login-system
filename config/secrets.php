<?php

$environmentPepper = getenv('PASSWORD_PEPPER');

if ($environmentPepper !== false && $environmentPepper !== '') {
    return [
        'password_pepper' => $environmentPepper,
    ];
}

$localSecrets = __DIR__ . '/secrets.local-backup.php';

if (!is_file($localSecrets)) {
    error_log('Password pepper configuration is missing.');
    http_response_code(500);
    exit('Security configuration is unavailable.');
}

return require $localSecrets;
