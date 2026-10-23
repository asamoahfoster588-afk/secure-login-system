
<?php

session_start();

require_once '../vendor/autoload.php';
require_once '../config/database.php';
require_once '../includes/Qr/SvgQrCodeProvider.php';

use RobThree\Auth\TwoFactorAuth;
use App\Qr\SvgQrCodeProvider;

// Only allow users who have passed the password step.
if (!isset($_SESSION['pending_user_id'])) {
    header('Location: login.php');
    exit;
}

$userId = (int) $_SESSION['pending_user_id'];

// Load the latest account status, role and 2FA information.
$stmt = $pdo->prepare(
    "SELECT
        users.id,
        users.username,
        users.two_factor_secret,
        users.two_factor_enabled,
        users.account_status,
        roles.role_name
     FROM users
     INNER JOIN roles ON users.role_id = roles.id
     WHERE users.id = ?
     LIMIT 1"
);

$stmt->execute([$userId]);
$user = $stmt->fetch();

// Reject missing or inactive accounts.
if (!$user || $user['account_status'] !== 'active') {
    $_SESSION = [];
    session_destroy();

    header('Location: login.php');
    exit;
}

// This page is only for accounts with 2FA already enabled.
if (
    (int) $user['two_factor_enabled'] !== 1 ||
    empty($user['two_factor_secret'])
) {
    header('Location: enroll-2fa.php');
    exit;
}

// Create a CSRF token for this verification form.
if (!isset($_SESSION['verify_csrf'])) {
    $_SESSION['verify_csrf'] = bin2hex(random_bytes(32));
}

$csrfToken = $_SESSION['verify_csrf'];
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedToken = $_POST['csrf_token'] ?? '';
    $code = trim($_POST['code'] ?? '');

    if (
        !is_string($postedToken) ||
        !hash_equals($csrfToken, $postedToken)
    ) {
        $error = 'Invalid request. Reload the page and try again.';

    } elseif (!preg_match('/^\d{6}$/', $code)) {
        $error = 'Please enter the six-digit authentication code.';

    } else {
        $qrProvider = new SvgQrCodeProvider();
        $tfa = new TwoFactorAuth($qrProvider, 'THE SQUAD');

        $valid = $tfa->verifyCode(
            $user['two_factor_secret'],
            $code
        );

        if ($valid) {
            // Replace the pending session with a fully authenticated session.
            session_regenerate_id(true);

            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role'] = $user['role_name'];

            unset(
                $_SESSION['pending_user_id'],
                $_SESSION['pending_username'],
                $_SESSION['pending_role'],
                $_SESSION['verify_csrf'],
                $_SESSION['enroll_csrf']
            );

            header('Location: dashboard.php');
            exit;

        } else {
            $error = 'Invalid authentication code. Please try again.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Two-Factor Verification | THE SQUAD</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            padding: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: Arial, Helvetica, sans-serif;
            color: #253b32;

            background:
                linear-gradient(
                    rgba(0, 44, 50, 0.40),
                    rgba(0, 44, 50, 0.40)
                ),
                url('https://images.unsplash.com/photo-1518837695005-2083093ee35b?auto=format&fit=crop&w=2200&q=90')
                center center / cover no-repeat fixed;
        }

        .verification-card {
            width: 100%;
            max-width: 470px;
            padding: 42px;
            border-radius: 18px;
            background: rgba(255, 255, 255, 0.97);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.28);
            text-align: center;
        }

        .security-icon {
            width: 68px;
            height: 68px;
            margin: 0 auto 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            background: #e6f3e6;
            color: #39764c;
        }

        .security-icon svg {
            width: 36px;
            height: 36px;
        }

        .eyebrow {
            margin-bottom: 10px;
            color: #55783b;
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 1.8px;
            text-transform: uppercase;
        }

        h1 {
            margin: 0 0 14px;
            color: #244a36;
            font-size: clamp(25px, 5vw, 32px);
            line-height: 1.2;
        }

        .description {
            margin: 0 auto 28px;
            max-width: 340px;
            color: #68756d;
            font-size: 14px;
            line-height: 1.7;
        }

        .error {
            margin-bottom: 20px;
            padding: 12px 14px;
            border: 1px solid #f0caca;
            border-radius: 8px;
            background: #fff1f1;
            color: #a32222;
            font-size: 13px;
            line-height: 1.5;
            text-align: left;
            overflow-wrap: anywhere;
        }

        form {
            text-align: left;
        }

        label {
            display: block;
            margin-bottom: 9px;
            color: #35483c;
            font-size: 13px;
            font-weight: bold;
        }

        #code {
            width: 100%;
            padding: 17px 12px;
            border: 1px solid #d5e1d7;
            border-radius: 9px;
            outline: none;
            background: #f8fbf7;
            color: #244a36;
            font-family: Arial, Helvetica, sans-serif;
            font-size: 28px;
            font-weight: bold;
            letter-spacing: 10px;
            text-align: center;
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        #code:focus {
            border-color: #5d8b5c;
            box-shadow: 0 0 0 3px rgba(85, 120, 59, 0.13);
        }

        #code::placeholder {
            color: #c2cdc3;
            letter-spacing: 8px;
        }

        .hint {
            margin: 10px 0 22px;
            color: #849087;
            font-size: 12px;
            line-height: 1.5;
        }

        .verify-button {
            width: 100%;
            padding: 15px 18px;
            border: none;
            border-radius: 8px;
            background: #39764c;
            color: white;
            font-size: 15px;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.2s, transform 0.2s;
        }

        .verify-button:hover {
            background: #2d603c;
        }

        .verify-button:active {
            transform: scale(0.99);
        }

        .card-footer {
            margin-top: 24px;
            padding-top: 17px;
            border-top: 1px solid #edf0eb;
            color: #899188;
            font-size: 11px;
        }

        @media (max-width: 520px) {
            body {
                padding: 16px;
                background-attachment: scroll;
            }

            .verification-card {
                padding: 30px 22px;
            }

            #code {
                font-size: 25px;
                letter-spacing: 7px;
            }
        }
    </style>
</head>

<body>

    <main class="verification-card">

        <div class="security-icon" aria-hidden="true">
            <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="1.7"
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11z"/>
                <path d="m9 12 2 2 4-4"/>
            </svg>
        </div>

        <div class="eyebrow">THE SQUAD · Account Security</div>

        <h1>Two-Factor Verification</h1>

        <p class="description">
            One more step to secure your account.
            Enter the six-digit code from your authenticator app
            to continue to your dashboard.
        </p>

        <?php if ($error !== ''): ?>
            <div class="error" role="alert">
                <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="verify-2fa.php">

            <input
                type="hidden"
                name="csrf_token"
                value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>"
            >

            <label for="code">Authentication Code</label>

            <input
                type="text"
                id="code"
                name="code"
                inputmode="numeric"
                pattern="[0-9]{6}"
                maxlength="6"
                minlength="6"
                autocomplete="one-time-code"
                placeholder="••••••"
                aria-describedby="code-hint"
                required
                autofocus
            >

            <p class="hint" id="code-hint">
                Open your authenticator app and enter the current six-digit code.
            </p>

            <button type="submit" class="verify-button">
                Verify and Continue
            </button>

        </form>

        <div class="card-footer">
            Secure access · THE SQUAD
        </div>

    </main>

</body>
</html>
