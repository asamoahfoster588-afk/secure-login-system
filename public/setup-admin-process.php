
<?php

session_start();

if (empty($_SESSION['admin_setup_authorized'])) {
    http_response_code(403);
    exit('Access denied.');
}

$setupEnabled = getenv('ADMIN_SETUP_ENABLED') === 'true';
$setupToken = getenv('ADMIN_SETUP_TOKEN');

if (!$setupEnabled || !is_string($setupToken) || $setupToken === '') {
    unset($_SESSION['admin_setup_authorized']);
    http_response_code(404);
    exit('Page not found.');
}

require_once __DIR__ . '/../config/database.php';
$secrets = require __DIR__ . '/../config/secrets.php';

$pepper = $secrets['password_pepper'] ?? '';

if (!is_string($pepper) || $pepper === '') {
    http_response_code(500);
    exit('Security configuration is unavailable.');
}

if (!defined('PASSWORD_ARGON2ID')) {
    http_response_code(500);
    exit('Required password hashing support is unavailable.');
}

$error = '';
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = (string) ($_POST['password'] ?? '');
    $confirmPassword = (string) ($_POST['confirm_password'] ?? '');

    if (strlen($password) < 12) {
        $error = 'Use a password with at least 12 characters.';
    } elseif (!hash_equals($password, $confirmPassword)) {
        $error = 'The passwords do not match.';
    } else {
        $hash = password_hash(
            $password . $pepper,
            PASSWORD_ARGON2ID
        );

        if ($hash === false) {
            $error = 'Password hashing failed.';
        } else {
            try {
                $pdo->beginTransaction();

                $stmt = $pdo->prepare(
                    "SELECT id
                     FROM public.users
                     WHERE username = :username
                       AND role_id = (
                           SELECT id
                           FROM public.roles
                           WHERE role_name = 'administrator'
                       )
                       AND account_status = 'active'
                     FOR UPDATE"
                );

                $stmt->execute(['username' => 'Foster']);
                $admin = $stmt->fetch(PDO::FETCH_ASSOC);

                if (!$admin) {
                    $pdo->rollBack();
                    $error = 'The existing active administrator was not found.';
                } else {
                    $update = $pdo->prepare(
                        "UPDATE public.users
                         SET password_hash = :password_hash,
                             updated_at = CURRENT_TIMESTAMP
                         WHERE id = :id"
                    );

                    $update->execute([
                        'password_hash' => $hash,
                        'id' => $admin['id'],
                    ]);

                    $pdo->commit();

                    unset($_SESSION['admin_setup_authorized']);
                    session_regenerate_id(true);

                    $success = true;
                }
            } catch (Throwable $e) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                error_log('Administrator recovery failed.');
                $error = 'Recovery failed. Check the server logs.';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Administrator Recovery</title>
</head>
<body>
    <h1>Reset Administrator Password</h1>

    <?php if ($success): ?>
        <p>Password reset successfully. You can now return to the login page.</p>
    <?php else: ?>
        <?php if ($error !== ''): ?>
            <p role="alert">
                <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
            </p>
        <?php endif; ?>

        <form method="post">
            <label for="password">New password</label>
            <input
                type="password"
                id="password"
                name="password"
                minlength="12"
                autocomplete="new-password"
                required
            >

            <label for="confirm_password">Confirm new password</label>
            <input
                type="password"
                id="confirm_password"
                name="confirm_password"
                minlength="12"
                autocomplete="new-password"
                required
            >

            <button type="submit">Reset Administrator Password</button>
        </form>
    <?php endif; ?>
</body>
</html>
