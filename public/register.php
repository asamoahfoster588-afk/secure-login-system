<?php

session_start();

require_once __DIR__ . '/../config/database.php';
$secrets = require __DIR__ . '/../config/secrets.php';

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';

    if (
        $username === '' ||
        $email === '' ||
        $password === '' ||
        $confirmPassword === ''
    ) {
        $error = 'All fields are required.';

    } elseif (strlen($username) > 100) {
        $error = 'Username cannot exceed 100 characters.';

    } elseif (strlen($email) > 254) {
        $error = 'Email address is too long.';

    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Enter a valid email address.';

    } elseif ($password !== $confirmPassword) {
        $error = 'Passwords do not match.';

    } elseif (strlen($password) < 12) {
        $error = 'Password must be at least 12 characters long.';

    } else {
        try {
            // Retrieve the Inputer role.
            $roleStmt = $pdo->prepare(
                "SELECT id
                 FROM roles
                 WHERE role_name = :role_name
                 LIMIT 1"
            );

            $roleStmt->execute([
                'role_name' => 'inputer'
            ]);

            $role = $roleStmt->fetch(PDO::FETCH_ASSOC);

            if (!$role) {
                throw new RuntimeException(
                    'Inputer role is not configured.'
                );
            }

            // Check for an existing account or pending request.
            $existingStmt = $pdo->prepare(
                "SELECT 1
                 FROM users
                 WHERE LOWER(username) = LOWER(:username)
                    OR LOWER(email) = LOWER(:email)

                 UNION ALL

                 SELECT 1
                 FROM registration_requests
                 WHERE LOWER(username) = LOWER(:request_username)
                    OR LOWER(email) = LOWER(:request_email)

                 LIMIT 1"
            );

            $existingStmt->execute([
                'username' => $username,
                'email' => $email,
                'request_username' => $username,
                'request_email' => $email
            ]);

            if ($existingStmt->fetchColumn()) {
                $error = 'That username or email may already be registered or awaiting review.';

            } else {
                // Use the same pepper and password hashing method as login.
                $passwordWithPepper =
                    $password . $secrets['password_pepper'];

                $passwordHash = password_hash(
                    $passwordWithPepper,
                    PASSWORD_ARGON2ID
                );

                if ($passwordHash === false) {
                    throw new RuntimeException(
                        'Password hashing failed.'
                    );
                }

                // Save the application, not an active user account.
                $stmt = $pdo->prepare(
                    "INSERT INTO registration_requests
                        (
                            username,
                            email,
                            password_hash,
                            requested_role_id,
                            request_status
                        )
                     VALUES
                        (
                            :username,
                            :email,
                            :password_hash,
                            :role_id,
                            'pending'
                        )"
                );

                $stmt->execute([
                    'username' => $username,
                    'email' => $email,
                    'password_hash' => $passwordHash,
                    'role_id' => $role['id']
                ]);

                $success = 'Your registration request has been submitted. '
                    . 'An administrator must approve it before you can log in.';
            }

        } catch (PDOException $e) {
            // Keep database details out of the public page.
            error_log('Registration database error: ' . $e->getMessage());

            $error = 'Unable to submit your request right now. '
                . 'Please try again later.';

        } catch (RuntimeException $e) {
            error_log('Registration configuration error: ' . $e->getMessage());

            $error = 'Registration is temporarily unavailable. '
                . 'Please contact the administrator.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Request an Account | Secure Login System</title>

    <style>
        :root {
            --forest: #173d2b;
            --forest-dark: #102b1e;
            --green: #286b45;
            --green-hover: #1e5436;
            --light-green: #eaf3ec;
            --gold: #d5b76a;
            --white: #ffffff;
            --text: #26352c;
            --muted: #6c7a70;
            --border: #dce5de;
            --error: #a62f2f;
            --error-bg: #fff0f0;
            --success: #22613b;
            --success-bg: #eaf7ee;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            padding: 35px 18px;

            font-family: "Segoe UI", Arial, sans-serif;
            color: var(--text);

            background:
                radial-gradient(
                    circle at 15% 15%,
                    rgba(93, 145, 103, 0.20),
                    transparent 30%
                ),
                radial-gradient(
                    circle at 85% 85%,
                    rgba(213, 183, 106, 0.12),
                    transparent 30%
                ),
                linear-gradient(
                    135deg,
                    var(--forest-dark),
                    var(--forest) 55%,
                    #254b34
                );
        }

        .page-wrapper {
            width: 100%;
            max-width: 490px;
        }

        .brand {
            text-align: center;
            margin-bottom: 24px;
            color: var(--white);
        }

        .brand-symbol {
            width: 66px;
            height: 66px;
            margin: 0 auto 13px;

            display: flex;
            align-items: center;
            justify-content: center;

            border: 1px solid rgba(213, 183, 106, 0.75);
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.08);

            color: var(--gold);
            font-size: 29px;
            font-weight: 700;
        }

        .brand h1 {
            font-size: 25px;
            letter-spacing: 3px;
            font-weight: 750;
        }

        .brand p {
            margin-top: 8px;
            color: #d6e4d9;
            font-size: 13px;
            letter-spacing: 0.4px;
        }

        .registration-card {
            width: 100%;
            padding: 34px;
            background: var(--white);
            border-radius: 16px;
            border-top: 5px solid var(--gold);

            box-shadow: 0 22px 60px rgba(0, 0, 0, 0.25);
        }

        .card-heading {
            margin-bottom: 25px;
        }

        .card-heading h2 {
            color: var(--forest);
            font-size: 25px;
            margin-bottom: 9px;
        }

        .card-heading p {
            color: var(--muted);
            font-size: 14px;
            line-height: 1.7;
        }

        .notice {
            padding: 13px 15px;
            margin-bottom: 22px;
            border-radius: 8px;
            font-size: 13px;
            line-height: 1.6;
        }

        .notice.error {
            color: var(--error);
            background: var(--error-bg);
            border-left: 4px solid var(--error);
        }

        .notice.success {
            color: var(--success);
            background: var(--success-bg);
            border-left: 4px solid var(--success);
        }

        .form-group {
            margin-bottom: 19px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #33473a;
            font-size: 13px;
            font-weight: 650;
        }

        .input-wrapper {
            position: relative;
        }

        .form-group input {
            display: block;
            width: 100%;
            min-height: 47px;
            padding: 12px 13px;

            border: 1px solid var(--border);
            border-radius: 8px;
            outline: none;

            background: #fbfcfb;
            color: var(--text);
            font: inherit;
            font-size: 14px;

            transition:
                border-color 0.2s,
                box-shadow 0.2s,
                background 0.2s;
        }

        .form-group input:focus {
            border-color: var(--green);
            background: var(--white);
            box-shadow: 0 0 0 3px rgba(40, 107, 69, 0.12);
        }

        .password-input {
            padding-right: 75px !important;
        }

        .toggle-password {
            position: absolute;
            top: 50%;
            right: 12px;
            transform: translateY(-50%);

            border: none;
            background: transparent;
            color: var(--green);
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
        }

        .toggle-password:hover {
            color: var(--green-hover);
            text-decoration: underline;
        }

        .password-hint {
            display: block;
            margin-top: 7px;
            color: var(--muted);
            font-size: 11px;
            line-height: 1.5;
        }

        .submit-button {
            width: 100%;
            min-height: 49px;
            margin-top: 5px;
            padding: 13px 18px;

            border: none;
            border-radius: 8px;
            background: var(--green);
            color: var(--white);

            font-size: 14px;
            font-weight: 700;
            cursor: pointer;

            transition:
                background 0.2s,
                transform 0.2s;
        }

        .submit-button:hover {
            background: var(--green-hover);
            transform: translateY(-1px);
        }

        .submit-button:focus-visible,
        .toggle-password:focus-visible,
        a:focus-visible {
            outline: 3px solid var(--gold);
            outline-offset: 3px;
        }

        .approval-note {
            display: flex;
            gap: 11px;
            align-items: flex-start;

            margin-top: 22px;
            padding: 14px;
            border-radius: 8px;
            background: var(--light-green);
            color: #365342;

            font-size: 12px;
            line-height: 1.7;
        }

        .approval-icon {
            color: var(--green);
            font-size: 17px;
            font-weight: 800;
        }

        .login-link {
            margin-top: 23px;
            text-align: center;
            font-size: 13px;
            color: var(--muted);
        }

        .login-link a {
            color: var(--green);
            font-weight: 700;
            text-decoration: none;
        }

        .login-link a:hover {
            text-decoration: underline;
        }

        .page-footer {
            margin-top: 25px;
            text-align: center;
            color: #c9d8cd;
            font-size: 11px;
            line-height: 1.8;
        }

        .page-footer span {
            color: var(--gold);
        }

        @media (max-width: 480px) {
            body {
                padding: 24px 14px;
            }

            .registration-card {
                padding: 25px 20px;
            }

            .brand h1 {
                font-size: 22px;
            }

            .card-heading h2 {
                font-size: 22px;
            }
        }
    </style>
</head>

<body>

    <main class="page-wrapper">

        <header class="brand">
            

            <h1>SAVE NATURE</h1>

            <p>Register Now . Be Part of the Solution</p>
        </header>

        <section class="registration-card">

            <div class="card-heading">
                <h2>Request an Account</h2>

                <p>
                    Complete the form below to request an Inputer account.
                    Your request will be reviewed by an administrator.
                </p>
            </div>

            <?php if ($error !== ''): ?>
                <div class="notice error" role="alert">
                    <strong>Request not submitted.</strong><br>
                    <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
                </div>
            <?php endif; ?>

            <?php if ($success !== ''): ?>

                <div class="notice success" role="status">
                    <strong>Request submitted successfully!</strong><br>
                    <?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?>
                </div>

                <div class="approval-note">
                    <span class="approval-icon" aria-hidden="true">✓</span>

                    <div>
                        <strong>What happens next?</strong><br>
                        An administrator must approve your request before
                        you can access the system.
                    </div>
                </div>

                <div class="login-link">
                    <a href="login.php">Return to Login</a>
                </div>

            <?php else: ?>

                <form
                    method="POST"
                    action="register.php"
                    autocomplete="on"
                >

                    <div class="form-group">
                        <label for="username">Username</label>

                        <input
                            type="text"
                            id="username"
                            name="username"
                            maxlength="100"
                            autocomplete="username"
                            placeholder="Choose a username"
                            required
                        >
                    </div>

                    <div class="form-group">
                        <label for="email">Email Address</label>

                        <input
                            type="email"
                            id="email"
                            name="email"
                            maxlength="254"
                            autocomplete="email"
                            placeholder="Enter your email address"
                            required
                        >
                    </div>

                    <div class="form-group">
                        <label for="password">Password</label>

                        <div class="input-wrapper">
                            <input
                                type="password"
                                id="password"
                                name="password"
                                class="password-input"
                                minlength="12"
                                autocomplete="new-password"
                                placeholder="Create a strong password"
                                required
                            >

                            <button
                                type="button"
                                class="toggle-password"
                                aria-controls="password"
                                aria-pressed="false"
                            >Show</button>
                        </div>

                        <small class="password-hint">
                            Use at least 12 characters.
                        </small>
                    </div>

                    <div class="form-group">
                        <label for="confirm_password">
                            Confirm Password
                        </label>

                        <div class="input-wrapper">
                            <input
                                type="password"
                                id="confirm_password"
                                name="confirm_password"
                                class="password-input"
                                minlength="12"
                                autocomplete="new-password"
                                placeholder="Enter your password again"
                                required
                            >

                            <button
                                type="button"
                                class="toggle-password"
                                aria-controls="confirm_password"
                                aria-pressed="false"
                            >Show</button>
                        </div>
                    </div>

                    <button type="submit" class="submit-button">
                        Submit Registration Request
                    </button>

                </form>

                <div class="approval-note">
                    <span class="approval-icon" aria-hidden="true">i</span>

                    <div>
                        <strong>Administrator approval required</strong><br>
                        Submitting this form does not activate your account.
                        You must wait for an administrator to approve it.
                    </div>
                </div>

                <div class="login-link">
                    Already have an account?
                    <a href="login.php">Back to Login</a>
                </div>

            <?php endif; ?>

        </section>

        <footer class="page-footer">
            Secure Login System<br>
            <span>Save Nature.Save Tomorrow</span>
        </footer>

    </main>

    <script>
        document.querySelectorAll('.toggle-password').forEach((button) => {
            button.addEventListener('click', () => {
                const password = document.getElementById(
                    button.getAttribute('aria-controls')
                );

                const isVisible = password.type === 'text';

                password.type = isVisible ? 'password' : 'text';
                button.textContent = isVisible ? 'Show' : 'Hide';

                button.setAttribute(
                    'aria-pressed',
                    String(!isVisible)
                );
            });
        });
    </script>

</body>
</html>
