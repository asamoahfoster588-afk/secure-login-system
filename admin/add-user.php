<?php

session_start();

require_once '../includes/auth.php';
require_once '../config/database.php';

requireAdministrator();

$secrets = require '../config/secrets.php';

$message = '';
$error = '';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $selectedRole = $_POST['role'] ?? '';
    $allowedRoles = ['inputer', 'reviewer', 'auditor'];
    $csrfToken = $_POST['csrf_token'] ?? '';

    if (
        !is_string($csrfToken) ||
        !hash_equals($_SESSION['csrf_token'], $csrfToken)
    ) {
        $error = 'Invalid form submission. Please refresh and try again.';

    } elseif (
        $username === '' ||
        $email === '' ||
        $password === '' ||
        $confirmPassword === ''
    ) {
        $error = 'All fields are required.';

    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';

    } elseif ($password !== $confirmPassword) {
        $error = 'Passwords do not match.';

    } elseif (strlen($password) < 12) {
     $error = 'Password must be at least 12 characters.';

    } elseif (!in_array($selectedRole, $allowedRoles, true)) {
    $error = 'Please select a valid account role.';

    } else {

        $passwordWithPepper =
            $password . $secrets['password_pepper'];

        $passwordHash = password_hash(
            $passwordWithPepper,
            PASSWORD_ARGON2ID
        );

       try {
    // Find the actual database ID for the selected role.
    $roleStmt = $pdo->prepare(
        "SELECT id
         FROM public.roles
         WHERE role_name = :role_name
         LIMIT 1"
    );

    $roleStmt->execute([
        'role_name' => $selectedRole
    ]);

    $roleId = $roleStmt->fetchColumn();

    if ($roleId === false) {
        $error = 'The selected role does not exist in the database.';
    } else {
        // Hash the password using your existing Argon2id + pepper method.
        $passwordWithPepper =
            $password . $secrets['password_pepper'];

        $passwordHash = password_hash(
            $passwordWithPepper,
            PASSWORD_ARGON2ID
        );

      $stmt = $pdo->prepare(
    "INSERT INTO users
        (username, email, password_hash, role_id, account_status)
     VALUES
        (:username, :email, :password_hash, :role_id, 'active')"
);

$stmt->execute([
    ':username' => $username,
    ':email' => $email,
    ':password_hash' => $passwordHash,
    ':role_id' => $roleId
]);

        $roleLabel = ucfirst($selectedRole);
        $message = $roleLabel . ' account created successfully.';

        // Generate a fresh CSRF token after successful creation.
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

 } catch (PDOException $e) {
    // Do not display database errors or sensitive details to users.
    $error = 'Unable to create the account. The username or email may already exist.';
 }
    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>Add Inputer | SAVE NATURE</title>

    <style>
        * {
            box-sizing: border-box;
        }

        :root {
            --green: #245b45;
            --green-dark: #183e30;
            --green-light: #e8f0e8;
            --sage: #dce8dc;
            --text: #25352c;
            --muted: #718078;
            --border: #d8e2d9;
            --white: #ffffff;
        }

        body {
            margin: 0;
            min-height: 100vh;
            padding: 35px 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: "Segoe UI", Arial, sans-serif;
            color: var(--text);
            background:
                radial-gradient(
                    circle at 10% 15%,
                    rgba(255, 255, 255, 0.85),
                    transparent 32%
                ),
                linear-gradient(
                    135deg,
                    #e4eee3,
                    #f4f5ed 55%,
                    #d4e3d7
                );
        }

        .page-wrapper {
            width: 100%;
            max-width: 1000px;
        }

        .top-navigation {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 15px;
            margin-bottom: 22px;
        }

        .brand {
            color: var(--green-dark);
            font-size: 19px;
            font-weight: 750;
            letter-spacing: 0.3px;
        }

        .brand small {
            display: block;
            margin-top: 3px;
            color: var(--muted);
            font-size: 12px;
            font-weight: 400;
            letter-spacing: 0;
        }

        .nav-links {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }

        .nav-links a {
            padding: 10px 14px;
            border: 1px solid #cad9cc;
            border-radius: 9px;
            color: var(--green-dark);
            background: rgba(255, 255, 255, 0.7);
            text-decoration: none;
            font-size: 13px;
            font-weight: 600;
            transition: 0.2s ease;
        }

        .nav-links a:hover {
            background: var(--green);
            border-color: var(--green);
            color: white;
        }

        .main-card {
            display: grid;
            grid-template-columns: 0.8fr 1.2fr;
            overflow: hidden;
            border: 1px solid rgba(255, 255, 255, 0.8);
            border-radius: 22px;
            background: var(--white);
            box-shadow: 0 22px 60px rgba(37, 75, 51, 0.13);
        }

        .intro-panel {
            position: relative;
            overflow: hidden;
            padding: 42px 32px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            color: white;
            background:
                linear-gradient(
                    150deg,
                    rgba(24, 62, 48, 0.97),
                    rgba(45, 103, 74, 0.94)
                );
        }

        .intro-panel::after {
            content: "";
            position: absolute;
            width: 250px;
            height: 250px;
            right: -105px;
            bottom: -90px;
            border: 1px solid rgba(255, 255, 255, 0.18);
            border-radius: 50%;
            box-shadow:
                0 0 0 25px rgba(255, 255, 255, 0.035),
                0 0 0 50px rgba(255, 255, 255, 0.025);
        }

        .panel-label {
            display: inline-block;
            width: fit-content;
            padding: 7px 11px;
            border: 1px solid rgba(255, 255, 255, 0.28);
            border-radius: 20px;
            color: #e2f1e4;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1.3px;
            text-transform: uppercase;
        }

        .intro-panel h1 {
            margin: 27px 0 15px;
            font-size: clamp(29px, 4vw, 40px);
            line-height: 1.12;
        }

        .intro-panel p {
            color: #dce9df;
            font-size: 14px;
            line-height: 1.8;
        }

        .admin-info {
            position: relative;
            z-index: 1;
            margin-top: 45px;
            padding-top: 22px;
            border-top: 1px solid rgba(255, 255, 255, 0.2);
        }

        .admin-info span {
            display: block;
            margin-bottom: 5px;
            color: #d0e1d4;
            font-size: 12px;
        }

        .admin-info strong {
            overflow-wrap: anywhere;
            font-size: 15px;
        }

        .form-panel {
            padding: 42px 38px;
        }

        .form-heading {
            margin-bottom: 28px;
        }

        .form-heading .eyebrow {
            color: var(--green);
            font-size: 11px;
            font-weight: 750;
            letter-spacing: 1.5px;
            text-transform: uppercase;
        }

        .form-heading h2 {
            margin: 8px 0;
            color: var(--green-dark);
            font-size: 27px;
        }

        .form-heading p {
            margin: 0;
            color: var(--muted);
            font-size: 13px;
            line-height: 1.6;
        }

        .notice {
            margin-bottom: 20px;
            padding: 13px 15px;
            border-radius: 9px;
            font-size: 13px;
            line-height: 1.6;
        }

        .success {
            color: #1d653d;
            border: 1px solid #b8dec5;
            background: #edf8f0;
        }

        .error {
            color: #a12f2f;
            border: 1px solid #f0c4c4;
            background: #fff0f0;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #35483b;
            font-size: 13px;
            font-weight: 650;
        }

        .form-group input {
            display: block;
            width: 100%;
            min-height: 47px;
            padding: 12px 14px;
            border: 1px solid var(--border);
            border-radius: 10px;
            outline: none;
            background: #fbfcfa;
            color: var(--text);
            font: inherit;
            font-size: 14px;
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        .form-group input:focus {
            border-color: #4d8a67;
            box-shadow: 0 0 0 3px rgba(77, 138, 103, 0.13);
            background: white;
        }

        .password-container {
            position: relative;
        }

        .password-container input {
            padding-right: 70px;
        }

        .show-password {
            position: absolute;
            top: 50%;
            right: 10px;
            transform: translateY(-50%);
            padding: 6px 8px;
            border: none;
            border-radius: 6px;
            color: var(--green);
            background: transparent;
            font: inherit;
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
        }

        .show-password:hover {
            background: var(--green-light);
        }

        .password-hint {
            display: block;
            margin-top: 7px;
            color: var(--muted);
            font-size: 11px;
        }

        .submit-button {
            width: 100%;
            min-height: 49px;
            margin-top: 4px;
            border: none;
            border-radius: 10px;
            color: white;
            background: var(--green);
            font: inherit;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            transition: background 0.2s, transform 0.2s;
        }

        .submit-button:hover {
            transform: translateY(-1px);
            background: var(--green-dark);
        }

        .submit-button:focus-visible,
        .show-password:focus-visible,
        .nav-links a:focus-visible {
            outline: 3px solid #8ab99a;
            outline-offset: 3px;
        }

        .form-footer {
            margin-top: 20px;
            padding-top: 18px;
            border-top: 1px solid #edf0eb;
            color: var(--muted);
            font-size: 12px;
            line-height: 1.6;
            text-align: center;
        }

        .page-footer {
            margin-top: 20px;
            color: #718078;
            font-size: 11px;
            text-align: center;
        }

        @media (max-width: 720px) {
            body {
                padding: 22px 14px;
            }

            .top-navigation {
                align-items: flex-start;
                flex-direction: column;
            }

            .main-card {
                grid-template-columns: 1fr;
                border-radius: 17px;
            }

            .intro-panel {
                padding: 28px 25px;
            }

            .intro-panel h1 {
                margin-top: 20px;
            }

            .admin-info {
                margin-top: 24px;
            }

            .form-panel {
                padding: 30px 23px;
            }

            .form-heading h2 {
                font-size: 24px;
            }
        }
    </style>
</head>

<body>

<div class="page-wrapper">

    <div class="top-navigation">
        <div class="brand">
            SAVE NATURE
            <small>Administration workspace</small>
        </div>

        <nav class="nav-links" aria-label="Admin navigation">
            <a href="users.php">User Management</a>
            <a href="../public/dashboard.php">Dashboard</a>
        </nav>
    </div>

    <main class="main-card">

        <section class="intro-panel">
            <div>
                <span class="panel-label">Administrator access</span>

                <h1>Add a new Inputer.</h1>

                <p>
                    Create an account for a new team member.
                    Set their login details carefully and use a
                    strong temporary password.
                </p>
            </div>

            <div class="admin-info">
                <span>Currently signed in as</span>

                <strong>
                    <?= htmlspecialchars(
                        $_SESSION['username'] ?? 'Administrator',
                        ENT_QUOTES,
                        'UTF-8'
                    ) ?>
                </strong>
            </div>
        </section>

        <section class="form-panel">

            <div class="form-heading">
                <span class="eyebrow">Account management</span>
                <h2>Create Inputer</h2>
                <p>
                    Enter the new user's details in the fields below.
                    All fields are required.
                </p>
            </div>

            <?php if ($message): ?>
                <div class="notice success" role="status">
                    <?= htmlspecialchars(
                        $message,
                        ENT_QUOTES,
                        'UTF-8'
                    ) ?>
                </div>
            <?php endif; ?>

            <?php if ($error): ?>
                <div class="notice error" role="alert">
                    <?= htmlspecialchars(
                        $error,
                        ENT_QUOTES,
                        'UTF-8'
                    ) ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="">

                <input
                    type="hidden"
                    name="csrf_token"
                    value="<?= htmlspecialchars(
                        $_SESSION['csrf_token'],
                        ENT_QUOTES,
                        'UTF-8'
                    ) ?>"
                >

                <div class="form-group">
                    <label for="username">Username</label>

                    <input
                        type="text"
                        id="username"
                        name="username"
                        autocomplete="off"
                        maxlength="100"
                        required
                    >
                </div>

                <div class="form-group">
                    <label for="email">Email address</label>

                    <input
                        type="email"
                        id="email"
                        name="email"
                        autocomplete="off"
                        maxlength="254"
                        required
                    >
                </div>

                <div class="form-group">
    <label for="role">Account role</label>

    <select
        id="role"
        name="role"
        required
        style="
            display: block;
            width: 100%;
            min-height: 47px;
            padding: 12px 14px;
            border: 1px solid var(--border);
            border-radius: 10px;
            background: #fbfcfa;
            color: var(--text);
            font: inherit;
        "
    >
        <option value="">Select a role</option>
        <option value="inputer">Inputer</option>
        <option value="reviewer">Reviewer</option>
        <option value="auditor">Auditor</option>
    </select>
</div>

                <div class="form-group">
                    <label for="password">Temporary password</label>

                    <div class="password-container">
                        <input
                            type="password"
                            id="password"
                            name="password"
                            minlength="12"
                            autocomplete="new-password"
                            required
                        >

                        <button
                            type="button"
                            class="show-password"
                            data-target="password"
                            aria-label="Show password"
                            aria-pressed="false"
                        >Show</button>
                    </div>

                    <span class="password-hint">
                        Use at least 12 characters.
                    </span>
                </div>

                <div class="form-group">
                    <label for="confirm_password">
                        Confirm password
                    </label>

                    <div class="password-container">
                        <input
                            type="password"
                            id="confirm_password"
                            name="confirm_password"
                            minlength="12"
                            autocomplete="new-password"
                            required
                        >

                        <button
                            type="button"
                            class="show-password"
                            data-target="confirm_password"
                            aria-label="Show confirm password"
                            aria-pressed="false"
                        >Show</button>
                    </div>
                </div>

                <button type="submit" class="submit-button">
                    Create Inputer Account
                </button>

            </form>

            <div class="form-footer">
                The new account will be assigned the Inputer role.
                Follow your system's account activation and 2FA
                enrollment process before the user signs in.
            </div>

        </section>

    </main>

    <footer class="page-footer">
        Save Nature · Administration workspace
    </footer>

</div>

<script>
document.querySelectorAll('.show-password').forEach(button => {
    button.addEventListener('click', () => {
        const input = document.getElementById(button.dataset.target);

        if (!input) {
            return;
        }

        const isVisible = input.type === 'password';

        input.type = isVisible ? 'text' : 'password';
        button.textContent = isVisible ? 'Hide' : 'Show';
        button.setAttribute('aria-pressed', String(isVisible));

        const fieldName =
            input.id === 'password' ? 'password' : 'confirm password';

        button.setAttribute(
            'aria-label',
            `${isVisible ? 'Hide' : 'Show'} ${fieldName}`
        );
    });
});
</script>

</body>
</html>