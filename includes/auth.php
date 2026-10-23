
<?php

function requireLogin(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }

    if (!isset($_SESSION['user_id'])) {
        header('Location: ../public/login.php');
        exit;
    }
}

function requireAdministrator(): void
{
    requireLogin();

    if (!hasRole('administrator')) {
        http_response_code(403);
        exit('Access denied.');
    }
}

function requireInputer(): void
{
    requireLogin();

    if (!hasRole('inputer')) {
        http_response_code(403);
        exit('Access denied.');
    }
}

function requireReviewer(): void
{
    requireLogin();

    if (!hasRole('reviewer')) {
        http_response_code(403);
        exit('Access denied.');
    }
}

function requireAuditor(): void
{
    requireLogin();

    if (!hasRole('auditor')) {
        http_response_code(403);
        exit('Access denied.');
    }
}

function hasRole(string $role): bool
{
    return isset($_SESSION['role'])
        && $_SESSION['role'] === $role;
}
