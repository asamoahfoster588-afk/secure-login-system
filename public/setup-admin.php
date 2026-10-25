
<?php


session_start();

$setupEnabled = getenv('ADMIN_SETUP_ENABLED') === 'true';
$setupToken = getenv('ADMIN_SETUP_TOKEN');

if (
    !$setupEnabled ||
    !is_string($setupToken) ||
    $setupToken === ''
) {
    http_response_code(404);
    exit('Page not found.');
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = (string) ($_POST['setup_token'] ?? '');

    if (!hash_equals($setupToken, $submittedToken)) {
        http_response_code(403);
        $error = 'Invalid setup token.';
    } else {
        $_SESSION['admin_setup_authorized'] = true;
        header('Location: setup-admin-process.php');
        exit;
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
    <h1>Administrator Recovery</h1>
    <p>Enter the temporary setup token to continue.</p>

    <?php if ($error !== ''): ?>
        <p role="alert">
            <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
        </p>
    <?php endif; ?>

    <form method="post">
        <label for="setup_token">Setup token</label>
        <input
            type="password"
            id="setup_token"
            name="setup_token"
            required
            autocomplete="off"
        >
        <button type="submit">Continue</button>
    </form>
</body>
</html>
