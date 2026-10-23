
<?php

session_start();

require_once '../vendor/autoload.php';
require_once '../config/database.php';
require_once '../includes/Qr/SvgQrCodeProvider.php';

use RobThree\Auth\TwoFactorAuth;
use App\Qr\SvgQrCodeProvider;

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

$userId = $_SESSION['user_id'];

$stmt = $pdo->prepare(
    "SELECT username, email, two_factor_secret, two_factor_enabled
     FROM users
     WHERE id = ?
     LIMIT 1"
);

$stmt->execute([$userId]);

$user = $stmt->fetch();

if (!$user) {
    die('User account not found.');
}

$qrProvider = new SvgQrCodeProvider();

$tfa = new TwoFactorAuth(
    $qrProvider,
    'THE SQUAD'
);

$error = '';
$success = '';

/*
 * Generate a secret if the account does not already have one.
 */
if (empty($user['two_factor_secret'])) {

    $secret = $tfa->createSecret();

    $stmt = $pdo->prepare(
        "UPDATE users
         SET two_factor_secret = ?
         WHERE id = ?"
    );

    $stmt->execute([
        $secret,
        $userId
    ]);

    $user['two_factor_secret'] = $secret;
}

/*
 * Verify the authenticator code.
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $code = trim($_POST['code'] ?? '');

    if (!preg_match('/^\d{6}$/', $code)) {

        $error = 'Please enter the 6-digit code from your authenticator app.';

    } else {

        $valid = $tfa->verifyCode(
            $user['two_factor_secret'],
            $code
        );

        if ($valid) {

            $stmt = $pdo->prepare(
                "UPDATE users
                 SET two_factor_enabled = 1
                 WHERE id = ?"
            );

            $stmt->execute([$userId]);

            $success = 'Two-factor authentication has been enabled successfully.';

        } else {

            $error = 'Invalid code. Please try again.';
        }
    }
}

/*
 * Generate the QR code.
 */
$qrCode = $tfa->getQRCodeImageAsDataUri(
    $user['username'],
    $user['two_factor_secret']
);

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>Set Up 2FA</title>

</head>

<body>

<h1>Set Up Two-Factor Authentication</h1>

<p>
    Account:
    <strong><?= htmlspecialchars($user['username']) ?></strong>
</p>

<?php if ($success): ?>

    <p style="color: green;">
        <?= htmlspecialchars($success) ?>
    </p>

<?php endif; ?>

<?php if ($error): ?>

    <p style="color: red;">
        <?= htmlspecialchars($error) ?>
    </p>

<?php endif; ?>

<h2>Step 1: Scan the QR Code</h2>

<p>
    Open your authenticator app and scan this QR code.
</p>

<img
    src="<?= htmlspecialchars($qrCode) ?>"
    alt="2FA QR Code"
    width="250"
    height="250"
>

<h2>Step 2: Verify Your Code</h2>

<p>
    Enter the 6-digit code shown in your authenticator app.
</p>

<form method="POST">

    <label for="code">
        Authentication Code
    </label>

    <br><br>

    <input
        type="text"
        id="code"
        name="code"
        inputmode="numeric"
        pattern="[0-9]{6}"
        maxlength="6"
        autocomplete="one-time-code"
        required
    >

    <br><br>

    <button type="submit">
        Enable 2FA
    </button>

</form>

</body>

</html>
