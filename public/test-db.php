
<?php

require_once __DIR__ . '/config/database.php';

try {
    $result = $pdo->query('SELECT current_database()');
    $databaseName = $result->fetchColumn();

    echo 'Connected successfully to: '
        . htmlspecialchars((string) $databaseName, ENT_QUOTES, 'UTF-8');
} catch (PDOException $e) {
    error_log($e->getMessage());
    http_response_code(500);
    echo 'The database test failed.';
}
