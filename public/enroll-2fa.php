```php
<?php

session_start();

require_once '../vendor/autoload.php';
require_once '../config/database.php';
require_once '../includes/Qr/SvgQrCodeProvider.php';

use RobThree\Auth\TwoFactorAuth;
use App\Qr\SvgQrCodeProvider;

// Only allow users who have passed the password check.
if (
    !isset(
        $_SESSION['pending_user_id'],
        $_SESSION['pending_username'],
        $_SESSION['pending_role']
    )
) {
    header('Location: login.php');
    exit;
}

$userId = (int) $_SESSION['pending_user_id'];

$stmt = $pdo->prepare(
    "SELECT username, two_factor_secret, two_factor_enabled
     FROM users
     WHERE id = ?
     LIMIT 1"
);

$stmt->execute([$userId]);
$user = $stmt->fetch();

if (!$user) {
    session_unset();
    session_destroy();
    header('Location: login.php');
    exit;
}

// If 2FA is already enabled, verification is required instead.
if ((int) $user['two_factor_enabled'] === 1) {
    header('Location: verify-2fa.php');
    exit;
}

$qrProvider = new SvgQrCodeProvider();
$tfa = new TwoFactorAuth($qrProvider, 'THE SQUAD');

$error = '';

$csrfToken = $_SESSION['enroll_csrf']
    ?? bin2hex(random_bytes(32));

$_SESSION['enroll_csrf'] = $csrfToken;

// Generate and save a secret if one does not exist.
if (empty($user['two_factor_secret'])) {
    $secret = $tfa->createSecret();

    $stmt = $pdo->prepare(
        "UPDATE users
         SET two_factor_secret = ?
         WHERE id = ? AND two_factor_enabled = FALSE"
    );

    $stmt->execute([$secret, $userId]);
    $user['two_factor_secret'] = $secret;
}

// Verify the first authenticator code.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedToken = $_POST['csrf_token'] ?? '';
    $code = trim($_POST['code'] ?? '');

    if (
        !is_string($postedToken) ||
        !hash_equals($csrfToken, $postedToken)
    ) {
        $error = 'Invalid request. Please reload the page and try again.';

    } elseif (!preg_match('/^\d{6}$/', $code)) {
        $error = 'Enter the six-digit code from your authenticator app.';

    } else {
        // Recheck the account before enabling 2FA.
        $stmt = $pdo->prepare(
            "SELECT two_factor_secret, two_factor_enabled
             FROM users
             WHERE id = ?
             LIMIT 1"
        );

        $stmt->execute([$userId]);
        $currentUser = $stmt->fetch();

        if (
            !$currentUser ||
            (int) $currentUser['two_factor_enabled'] === 1 ||
            empty($currentUser['two_factor_secret'])
        ) {
            $error = 'Enrollment could not be completed. Please log in again.';

        } elseif (
            $tfa->verifyCode($currentUser['two_factor_secret'], $code)
        ) {
            $stmt = $pdo->prepare(
                "UPDATE users
                 SET two_factor_enabled = True
                 WHERE id = ? AND two_factor_enabled = FALSE"
            );

            $stmt->execute([$userId]);

            // Only grant full access after successful enrollment.
            if ($stmt->rowCount() === 1) {
                session_regenerate_id(true);

                $_SESSION['user_id'] = $userId;
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $_SESSION['pending_role'];

                unset(
                    $_SESSION['pending_user_id'],
                    $_SESSION['pending_username'],
                    $_SESSION['pending_role'],
                    $_SESSION['enroll_csrf']
                );

                header('Location: dashboard.php');
                exit;
            }

            $error = 'Enrollment could not be completed. Please log in again.';

        } else {
            $error = 'Incorrect code. Check your authenticator app and try again.';
        }
    }
}

$qrCode = $tfa->getQRCodeImageAsDataUri(
    $user['username'],
    $user['two_factor_secret']
);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>First-Time 2FA Enrollment | Secure Login</title>

    <style>
        :root {
            --forest: #173f2b;
            --forest-dark: #102c1e;
            --forest-light: #245b3b;
            --gold: #d9b45b;
            --gold-light: #f3e4b5;
            --white: #ffffff;
            --background: #f5f7f3;
            --text: #24352a;
            --muted: #69766d;
            --border: #e0e7df;
            --error-bg: #fff0ef;
            --error-text: #a52d2d;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            padding: 35px 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: "Segoe UI", Arial, sans-serif;
            color: var(--text);
            background:
                radial-gradient(
                    circle at top left,
                    rgba(217, 180, 91, 0.13),
                    transparent 35%
                ),
                linear-gradient(
                    135deg,
                    var(--forest-dark),
                    var(--forest),
                    #28583a
                );
        }

        .page-wrapper {
            width: 100%;
            max-width: 510px;
        }

        .brand {
            text-align: center;
            margin-bottom: 24px;
            color: var(--white);
        }

        .brand-icon {
            width: 58px;
            height: 58px;
            margin: 0 auto 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 1px solid rgba(217, 180, 91, 0.65);
            border-radius: 16px;
            color: var(--gold);
            background: rgba(255, 255, 255, 0.07);
            font-size: 27px;
        }

        .brand h1 {
            margin: 0;
            font-size: 23px;
            letter-spacing: 2px;
            font-weight: 750;
        }

        .brand p {
            margin: 8px 0 0;
            color: #d5e0d7;
            font-size: 12px;
            letter-spacing: 1.3px;
        }

        .enrollment-card {
            overflow: hidden;
            background: var(--white);
            border-radius: 18px;
            border-top: 5px solid var(--gold);
            box-shadow: 0 22px 65px rgba(0, 0, 0, 0.24);
        }

        .card-content {
            padding: 30px;
        }

        .page-heading {
            text-align: center;
            margin-bottom: 23px;
        }

        .page-heading h2 {
            margin: 0 0 10px;
            color: var(--forest);
            font-size: 25px;
        }

        .page-heading p {
            margin: 0;
            color: var(--muted);
            font-size: 14px;
            line-height: 1.7;
        }

        .account-box {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 13px 15px;
            margin-bottom: 25px;
            background: #f2f6f1;
            border: 1px solid #e1e9df;
            border-radius: 11px;
        }

        .account-icon {
            width: 39px;
            height: 39px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            background: #dfeadf;
            color: var(--forest);
            border-radius: 50%;
            font-size: 18px;
        }

        .account-details {
            min-width: 0;
        }

        .account-details span {
            display: block;
            margin-bottom: 4px;
            color: var(--muted);
            font-size: 12px;
        }

        .account-details strong {
            display: block;
            overflow-wrap: anywhere;
            color: var(--forest);
            font-size: 15px;
        }

        .step {
            margin-bottom: 23px;
        }

        .step-heading {
            display: flex;
            align-items: center;
            gap: 11px;
            margin-bottom: 12px;
        }

        .step-number {
            width: 31px;
            height: 31px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            background: var(--forest);
            color: var(--white);
            border-radius: 50%;
            font-size: 13px;
            font-weight: 700;
        }

        .step-heading h3 {
            margin: 0;
            color: var(--forest);
            font-size: 16px;
        }

        .step-description {
            margin: 0 0 16px;
            color: var(--muted);
            font-size: 13px;
            line-height: 1.7;
        }

        .qr-container {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 18px;
            background: var(--background);
            border: 1px solid var(--border);
            border-radius: 13px;
        }

        .qr-container img {
            display: block;
            width: 220px;
            max-width: 100%;
            height: auto;
            aspect-ratio: 1 / 1;
            padding: 7px;
            background: var(--white);
            border: 1px solid #e6e6e6;
            border-radius: 8px;
        }

        .qr-caption {
            margin: 11px 0 0;
            color: var(--muted);
            font-size: 12px;
            text-align: center;
        }

        .error-message {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            margin-bottom: 22px;
            padding: 13px 14px;
            border: 1px solid #f2cfcc;
            border-radius: 10px;
            background: var(--error-bg);
            color: var(--error-text);
            font-size: 13px;
            line-height: 1.6;
        }

        .error-symbol {
            font-weight: 800;
            font-size: 16px;
        }

        .form-group {
            margin-top: 18px;
        }

        .form-group label {
            display: block;
            margin-bottom: 9px;
            color: var(--text);
            font-size: 13px;
            font-weight: 650;
        }

        .code-input {
            width: 100%;
            padding: 14px 12px;
            border: 1px solid #cbd6ca;
            border-radius: 9px;
            outline: none;
            background: #fcfdfb;
            color: var(--forest);
            font-family: inherit;
            font-size: 23px;
            font-weight: 700;
            letter-spacing: 8px;
            text-align: center;
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        .code-input::placeholder {
            color: #a9b3a9;
            letter-spacing: 5px;
        }

        .code-input:focus {
            border-color: var(--forest-light);
            box-shadow: 0 0 0 3px rgba(36, 91, 59, 0.12);
        }

        .verify-button {
            width: 100%;
            margin-top: 18px;
            padding: 15px 18px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 9px;
            border: none;
            border-radius: 9px;
            background: var(--forest);
            color: var(--white);
            font-family: inherit;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            transition: background 0.2s, transform 0.2s;
        }

        .verify-button:hover {
            background: var(--forest-light);
            transform: translateY(-1px);
        }

        .security-note {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            margin-top: 23px;
            padding: 13px;
            border: 1px solid #eee2bd;
            border-radius: 10px;
            background: #fffaf0;
            color: #6b5a2d;
            font-size: 12px;
            line-height: 1.7;
        }

        .security-note strong {
            color: #5a4820;
        }

        .card-footer {
            padding: 17px 25px;
            border-top: 1px solid var(--border);
            background: #fafbf9;
            color: var(--muted);
            font-size: 11px;
            line-height: 1.7;
            text-align: center;
        }

        .card-footer strong {
            color: var(--forest);
        }

        @media (max-width: 480px) {
            body {
                padding: 24px 12px;
            }

            .brand h1 {
                font-size: 20px;
            }

            .card-content {
                padding: 23px 19px;
            }

            .page-heading h2 {
                font-size: 22px;
            }

            .qr-container img {
                width: 195px;
            }

            .code-input {
                font-size: 21px;
                letter-spacing: 6px;
            }
        }
    </style>
</head>

<body>

    <main class="page-wrapper">

        <header class="brand">
            <div class="brand-icon" aria-hidden="true">&#128274;</div>
            <h1>SECURE LOGIN</h1>
            <p>SECURITY &bull; TRUST &bull; ACCOUNTABILITY</p>
        </header>

        <section class="enrollment-card">

            <div class="card-content">

                <div class="page-heading">
                    <h2>Secure Your Account</h2>
                    <p>
                        One more step to protect your account.
                        Set up two-factor authentication before continuing.
                    </p>
                </div>

                <div class="account-box">
                    <div class="account-icon" aria-hidden="true">
                        &#128100;
                    </div>

                    <div class="account-details">
                        <span>Account being secured</span>
                        <strong>
                            <?= htmlspecialchars(
                                $user['username'],
                                ENT_QUOTES,
                                'UTF-8'
                            ) ?>
                        </strong>
                    </div>
                </div>

                <?php if ($error !== ''): ?>
                    <div class="error-message" role="alert">
                        <span class="error-symbol" aria-hidden="true">!</span>
                        <span>
                            <?= htmlspecialchars(
                                $error,
                                ENT_QUOTES,
                                'UTF-8'
                            ) ?>
                        </span>
                    </div>
                <?php endif; ?>

                <section class="step">
                    <div class="step-heading">
                        <span class="step-number">1</span>
                        <h3>Scan the QR Code</h3>
                    </div>

                    <p class="step-description">
                        Open your authenticator app, such as Google
                        Authenticator or Microsoft Authenticator.
                        Scan the QR code below to add your account.
                    </p>

                    <div class="qr-container">
                        <img
                            src="<?= htmlspecialchars(
                                $qrCode,
                                ENT_QUOTES,
                                'UTF-8'
                            ) ?>"
                            alt="Authenticator setup QR code"
                            width="220"
                            height="220"
                        >
                    </div>

                    <p class="qr-caption">
                        Scan this code using your authenticator app.
                    </p>
                </section>

                <section class="step">
                    <div class="step-heading">
                        <span class="step-number">2</span>
                        <h3>Verify Your Code</h3>
                    </div>

                    <p class="step-description">
                        Enter the current six-digit code displayed
                        in your authenticator app to complete setup.
                    </p>

                    <form method="POST" action="enroll-2fa.php">

                        <input
                            type="hidden"
                            name="csrf_token"
                            value="<?= htmlspecialchars(
                                $csrfToken,
                                ENT_QUOTES,
                                'UTF-8'
                            ) ?>"
                        >

                        <div class="form-group">
                            <label for="code">
                                Six-digit authentication code
                            </label>

                            <input
                                class="code-input"
                                type="text"
                                id="code"
                                name="code"
                                inputmode="numeric"
                                pattern="[0-9]{6}"
                                minlength="6"
                                maxlength="6"
                                autocomplete="one-time-code"
                                placeholder="000000"
                                aria-describedby="code-help"
                                required
                            >
                        </div>

                        <button class="verify-button" type="submit">
                            <span aria-hidden="true">&#10003;</span>
                            Verify and Continue
                        </button>

                    </form>
                </section>

                <div class="security-note">
                    <span aria-hidden="true">&#128274;</span>
                    <div>
                        <strong>Security notice</strong><br>
                        Your dashboard remains protected until enrollment
                        is verified. Never share your authentication code
                        or QR setup code with anyone.
                    </div>
                </div>

            </div>

            <footer class="card-footer">
                <strong>SECURE LOGIN</strong><br>
                Account protection through two-factor authentication.
            </footer>

        </section>

    </main>

</body>
</html>
```