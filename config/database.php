<?php

$useEnvironment = getenv('DB_HOST') !== false
    && getenv('DB_HOST') !== '';

if (!$useEnvironment) {
    $localConfig = __DIR__ . '/database.local-backup.php';

    if (!is_file($localConfig)) {
        error_log('Local database configuration is missing.');
        http_response_code(500);
        exit('Database configuration is unavailable.');
    }

    require_once $localConfig;
    return;
}

$host = getenv('DB_HOST');
$port = getenv('DB_PORT') ?: '5432';
$dbname = getenv('DB_NAME');
$username = getenv('DB_USER');
$password = getenv('DB_PASSWORD');

if (!$dbname || !$username || $password === false) {
    error_log('Production database environment variables are incomplete.');
    http_response_code(500);
    exit('Database configuration is incomplete.');
}

$dsn = "pgsql:host=$host;port=$port;dbname=$dbname";

try {
    $pdo = new PDO($dsn, $username, $password, [
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
} catch (PDOException $e) {
    error_log('Database connection failed: ' . $e->getMessage());
    http_response_code(500);
    exit('Database connection failed. Check the server configuration.');
}
