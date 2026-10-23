<?php

session_start();

require_once __DIR__ . '/../config/database.php';
$secrets = require __DIR__ . '/../config/secrets.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');

    if ($username === '' || $password === '') {
        $error = 'Username and password are required.';
    } else {
        $sql = "
            SELECT
                users.id,
                users.username,
                users.password_hash,
                users.two_factor_enabled,
                users.account_status,
                roles.role_name
            FROM users
            INNER JOIN roles
                ON users.role_id = roles.id
            WHERE users.username = :username
            LIMIT 1
        ";

        $stmt = $pdo->prepare($sql);
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user === false) {
            $error = 'Invalid username or password.';
        } elseif ($user['account_status'] === 'pending') {
            $error = 'Your registration request is awaiting administrator approval.';
        } elseif ($user['account_status'] !== 'active') {
            $error = 'Your account is not active. Please contact the administrator.';
        } else {
            $passwordWithPepper = $password . $secrets['password_pepper'];

            if (!password_verify($passwordWithPepper, $user['password_hash'])) {
                $error = 'Invalid username or password.';
            } else {
                session_regenerate_id(true);

                unset(
                    $_SESSION['user_id'],
                    $_SESSION['username'],
                    $_SESSION['role'],
                    $_SESSION['pending_user_id'],
                    $_SESSION['pending_username'],
                    $_SESSION['pending_role']
                );

                $_SESSION['pending_user_id'] = (int) $user['id'];
                $_SESSION['pending_username'] = $user['username'];
                $_SESSION['pending_role'] = $user['role_name'];

                $twoFactorEnabled = (bool) $user['two_factor_enabled'];

                $redirectPath = $twoFactorEnabled ? 'verify-2fa.php' : 'enroll-2fa.php';
                header('Location: ' . $redirectPath);
                exit;
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: Arial, Helvetica, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            background:
                linear-gradient(
                    rgba(3, 48, 55, 0.18),
                    rgba(3, 48, 55, 0.18)
                ),
                url('https://images.unsplash.com/photo-1518837695005-2083093ee35b?auto=format&fit=crop&w=2200&q=90')
                center / cover no-repeat fixed;
        }

        .login-layout {
            display: grid;
            grid-template-columns: 40% 60%;
            width: 100%;
            max-width: 1400px;
            min-height: 590px;
            overflow: hidden;
            border-radius: 4px;
            box-shadow: 0 15px 45px rgba(0, 0, 0, 0.25);
            background: white;
        }

        .login-box {
            background: #fff;
            padding: 55px 42px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            min-width: 0;
        }

        .login-box h1 {
            color: #17365d;
            font-size: 29px;
            letter-spacing: 1px;
            margin: 0 0 30px;
        }

        .login-box label {
            display: block;
            margin-bottom: 7px;
            color: #38464b;
            font-size: 13px;
            font-weight: 600;
        }

        input[type="text"],
        input[type="password"] {
            width: 100%;
            min-width: 0;
            padding: 13px 15px;
            margin: 0 0 19px;
            border: 1px solid #dce6e4;
            border-radius: 7px;
            background: #f2f8f7;
            color: #263238;
            font-size: 14px;
            outline: none;
        }

        input:focus {
            border-color: #26bdb6;
            box-shadow: 0 0 0 3px rgba(38, 189, 182, 0.13);
        }

        .password-container {
            display: flex;
            align-items: stretch;
            gap: 7px;
            margin: 0 0 19px;
        }

        .password-container input {
            flex: 1;
            width: 0;
            margin: 0;
        }

        .show-password {
            width: auto;
            min-width: 62px;
            padding: 0 10px;
            margin: 0;
            border: 1px solid #dce6e4;
            border-radius: 7px;
            background: #edf2f0;
            color: #33443d;
            cursor: pointer;
        }

        .show-password:hover {
            background: #dce9e2;
        }

        .login-box form > button[type="submit"] {
            width: 100%;
            padding: 14px;
            margin-top: 2px;
            border: none;
            border-radius: 7px;
            background: #20bdb5;
            color: white;
            font-size: 14px;
            font-weight: bold;
            letter-spacing: 0.5px;
            cursor: pointer;
            transition: background 0.2s;
        }

        .login-box form > button[type="submit"]:hover {
            background: #159b95;
        }

        .error {
            margin-bottom: 18px;
            padding: 11px 12px;
            border-radius: 6px;
            background: #fff0f0;
            color: #b00020;
            font-size: 13px;
            overflow-wrap: anywhere;
        }

        .register-text {
            margin: 24px 0 9px;
            color: #68746f;
            font-size: 13px;
        }

        .register-link {
            display: block;
            text-align: center;
            padding: 12px;
            border: 1px solid #20bdb5;
            border-radius: 7px;
            color: #138c86;
            font-size: 14px;
            font-weight: bold;
            transition: background 0.2s;
        }

        .register-link:hover {
            background: #e8f9f7;
        }

        .nature-panel {
            position: relative;
            display: flex;
            align-items: flex-end;
            justify-content: center;
            padding: 45px;
            min-width: 0;
            color: white;
            background:
                linear-gradient(
                    180deg,
                    rgba(0, 50, 57, 0.02) 15%,
                    rgba(0, 42, 48, 0.65) 100%
                ),
                url('https://images.unsplash.com/photo-1518837695005-2083093ee35b?auto=format&fit=crop&w=1800&q=90')
                center / cover no-repeat;
        }

        .nature-message {
            position: relative;
            width: 100%;
            text-align: right;
        }

        .nature-message h2 {
            margin: 0;
            font-size: clamp(28px, 3.5vw, 52px);
            line-height: 1.1;
            letter-spacing: 1px;
            text-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
        }

        .nature-message p {
            margin: 10px 0 0;
            font-size: 16px;
            letter-spacing: 2px;
            text-transform: uppercase;
            text-shadow: 0 2px 8px rgba(0, 0, 0, 0.4);
        }

        @media (max-width: 760px) {
            body {
                padding: 14px;
                background-attachment: scroll;
            }

            .login-layout {
                grid-template-columns: 1fr;
                max-width: 460px;
                min-height: 0;
                border-radius: 12px;
            }

            .login-box {
                padding: 35px 27px;
                order: 1;
            }

            .nature-panel {
                order: 2;
                min-height: 210px;
                padding: 25px;
                background-position: center;
            }

            .nature-message h2 {
                font-size: 30px;
            }

            .nature-message p {
                font-size: 12px;
            }
        }

        @media (max-width: 360px) {
            .login-box {
                padding: 28px 18px;
            }

            .password-container {
                gap: 5px;
            }

            .show-password {
                min-width: 54px;
                padding: 0 7px;
            }
        }
    </style>
</head>

<body>
    <main class="login-layout">
        <section class="login-box">
            <h1>Login</h1>

            <?php if ($error): ?>
                <div class="error">
                    <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
                </div>
            <?php endif; ?>

            <form method="POST" novalidate>
                <label for="username">Username</label>
                <input
                    type="text"
                    id="username"
                    name="username"
                    autocomplete="username"
                    required
                >

                <label for="password">Password</label>
                <div class="password-container">
                    <input
                        type="password"
                        id="password"
                        name="password"
                        autocomplete="current-password"
                        required
                    >
                    <button
                        type="button"
                        id="togglePassword"
                        class="show-password"
                    >
                        Show
                    </button>
                </div>

                <button type="submit">Login</button>
            </form>

            <p class="register-text">Don't have an account?</p>
            <a class="register-link" href="register.php">Create Account</a>
        </section>

        <section class="nature-panel" aria-label="Nature background">
            <div class="nature-message">
                <h2>Save Nature,<br>Save Tomorrow.</h2>
                <p>Protect Our Planet</p>
            </div>
        </section>
    </main>

    <script>
        const passwordInput = document.getElementById('password');
        const togglePassword = document.getElementById('togglePassword');

        if (passwordInput && togglePassword) {
            togglePassword.addEventListener('click', () => {
                const isPassword = passwordInput.type === 'password';
                passwordInput.type = isPassword ? 'text' : 'password';
                togglePassword.textContent = isPassword ? 'Hide' : 'Show';
            });
        }
    </script>
</body>
</html>

