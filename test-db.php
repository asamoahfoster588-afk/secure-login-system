<?php

require_once __DIR__ . '/config/database.php';

try {
    $result = $pdo->query('SELECT current_database()')->fetchColumn();

    echo 'Connected successfully to: '
        . htmlspecialchars($result, ENT_QUOTES, 'UTF-8');
} catch (PDOException $e) {
    error_log($e->getMessage());
    echo 'The database test failed.';
}