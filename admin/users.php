
<?php
session_start();

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';

requireAdministrator();

// CSRF protection for user removal.
if (empty($_SESSION['user_management_csrf'])) {
    $_SESSION['user_management_csrf'] = bin2hex(random_bytes(32));
}

$csrfToken = $_SESSION['user_management_csrf'];
$successMessage = $_SESSION['user_management_success'] ?? '';
$errorMessage = '';

unset($_SESSION['user_management_success']);

// Handle removal requests before any HTML output.
if (
    $_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_POST['remove_user'])
) {
    $token = $_POST['csrf_token'] ?? '';
    $userId = filter_input(
        INPUT_POST,
        'user_id',
        FILTER_VALIDATE_INT
    );

    if (
        !is_string($token)
        || !hash_equals($csrfToken, $token)
    ) {
        $errorMessage =
            'Invalid security token. Refresh the page and try again.';

    } elseif (!$userId || $userId < 1) {
        $errorMessage = 'Invalid user account.';

    } elseif (
        !isset($_SESSION['user_id'])
        || (int) $userId === (int) $_SESSION['user_id']
    ) {
        $errorMessage =
            'You cannot remove your own account.';

    } else {
        try {
            // Confirm the target exists and is an Inputer.
            $check = $pdo->prepare(
                "SELECT users.id
                 FROM users
                 INNER JOIN roles
                     ON users.role_id = roles.id
                 WHERE users.id = :id
                   AND roles.role_name = 'inputer'"
            );

            $check->execute([':id' => $userId]);

            if (!$check->fetchColumn()) {
                $errorMessage =
                    'User not found or the account is not an Inputer.';
            } else {
                // Attempt deletion. Related database records may
                // prevent deletion; the error is handled below.
                $delete = $pdo->prepare(
                    'DELETE FROM users WHERE id = :id'
                );

                $delete->execute([':id' => $userId]);

                $_SESSION['user_management_success'] =
                    'Inputer account removed successfully.';

                header('Location: ' . $_SERVER['PHP_SELF']);
                exit;
            }

        } catch (PDOException $e) {
            error_log('User removal failed: ' . $e->getMessage());

            $errorMessage =
                'The account could not be removed. Related records may need to be handled first.';
        }
    }
}

// Retrieve users for the existing table.
$stmt = $pdo->query(
    "SELECT
        users.id,
        users.username,
        users.email,
        roles.role_name,
        users.account_status,
        users.two_factor_enabled,
        users.created_at
     FROM users
     INNER JOIN roles
        ON users.role_id = roles.id
     ORDER BY users.id ASC"
);

$users = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management | THE SQUAD</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            padding: 30px 18px;
            font-family: Arial, Helvetica, sans-serif;
            color: #263b30;

            background:
                linear-gradient(
                    rgba(0, 43, 48, 0.42),
                    rgba(0, 43, 48, 0.42)
                ),
                url('https://images.unsplash.com/photo-1518837695005-2083093ee35b?auto=format&fit=crop&w=2200&q=90')
                center center / cover no-repeat fixed;
        }

        .management-panel {
            width: 100%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 36px;
            border-radius: 16px;
            background: rgba(255, 255, 255, 0.97);
            box-shadow: 0 18px 55px rgba(0, 0, 0, 0.25);
        }

        .page-heading {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 18px;
            padding-bottom: 24px;
            border-bottom: 1px solid #e5ece5;
        }

        .eyebrow {
            margin: 0 0 8px;
            color: #55783b;
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 1.8px;
            text-transform: uppercase;
        }

        h1 {
            margin: 0;
            color: #244a36;
            font-size: clamp(26px, 4vw, 34px);
        }

        .welcome {
            margin: 12px 0 0;
            color: #68756d;
            font-size: 14px;
            line-height: 1.7;
            overflow-wrap: anywhere;
        }

        .role-label {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            background: #e7f3e7;
            color: #39764c;
            font-size: 12px;
            font-weight: bold;
        }

        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 24px 0;
        }

        .button {
            display: inline-block;
            padding: 12px 17px;
            border: 1px solid transparent;
            border-radius: 7px;
            background: #39764c;
            color: white;
            font-size: 13px;
            font-weight: bold;
            text-decoration: none;
            text-align: center;
            transition: background 0.2s;
        }

        .button:hover {
            background: #2d603c;
        }

        .button-secondary {
            background: #e9f3ed;
            color: #315d40;
            border-color: #d5e5d9;
        }

        .button-secondary:hover {
            background: #d9eade;
        }

        .button-logout {
            background: #fff0ed;
            color: #a33c31;
            border-color: #f1d5d0;
        }

        .button-logout:hover {
            background: #fbe0db;
        }

        .section-heading {
            margin: 28px 0 6px;
            color: #244a36;
            font-size: 21px;
        }

        .section-description {
            margin: 0 0 20px;
            color: #778279;
            font-size: 13px;
            line-height: 1.6;
        }

        .table-container {
            width: 100%;
            overflow-x: auto;
            border: 1px solid #e1e9e1;
            border-radius: 10px;
        }

        table {
            width: 100%;
            min-width: 760px;
            border-collapse: collapse;
            background: white;
        }

        th {
            padding: 15px 14px;
            background: #edf5ed;
            color: #315d40;
            font-size: 12px;
            font-weight: bold;
            text-align: left;
            white-space: nowrap;
        }

        td {
            padding: 15px 14px;
            border-top: 1px solid #edf0eb;
            color: #47564b;
            font-size: 13px;
            overflow-wrap: anywhere;
        }

        tbody tr:hover {
            background: #f8fbf7;
        }

        .status {
            display: inline-block;
            padding: 5px 9px;
            border-radius: 20px;
            background: #f0f2f0;
            color: #59635b;
            font-size: 11px;
            font-weight: bold;
            text-transform: capitalize;
            white-space: nowrap;
        }

        .status-active {
            background: #e4f5e7;
            color: #26733b;
        }

        .status-pending {
            background: #fff2d8;
            color: #895b10;
        }

        .status-inactive,
        .status-locked {
            background: #fde8e7;
            color: #a12e2e;
        }

        .twofa-enabled {
            color: #26733b;
            font-weight: bold;
        }

        .twofa-disabled {
            color: #a12e2e;
            font-weight: bold;
        }

        .empty-state {
            padding: 28px;
            color: #778279;
            text-align: center;
            font-size: 14px;
        }

        .page-footer {
            margin-top: 28px;
            padding-top: 18px;
            border-top: 1px solid #e5ece5;
            color: #899188;
            font-size: 11px;
            text-align: center;
        }

        @media (max-width: 600px) {
            body {
                padding: 14px 10px;
                background-attachment: scroll;
            }

            .management-panel {
                padding: 23px 16px;
                border-radius: 12px;
            }

            .page-heading {
                align-items: flex-start;
            }

            .actions {
                flex-direction: column;
            }

            .actions .button {
                width: 100%;
            }
        }

        .button-remove {
    background: #fff0ed;
    color: #a33c31;
    border: 1px solid #f1d5d0;
}

.button-remove:hover {
    background: #a33c31;
    color: #fff;
}

.protected-label {
    color: #778279;
    font-size: 12px;
    font-weight: bold;
}

.notice {
    margin: 18px 0;
    padding: 13px 16px;
    border-radius: 8px;
    font-size: 14px;
    line-height: 1.6;
}

.success {
    background: #e8f5e9;
    color: #205b2b;
    border: 1px solid #c6e5ca;
}

.error {
    background: #fff0ef;
    color: #a52d2d;
    border: 1px solid #f2cfcc;
}
    </style>
</head>

<body>

    <main class="management-panel">

        <header class="page-heading">
            <div>
                <p class="eyebrow">THE SQUAD · Administration</p>
                <h1>User Management</h1>

                <p class="welcome">
                    Welcome,
                    <strong><?= htmlspecialchars(
                        $_SESSION['username'],
                        ENT_QUOTES,
                        'UTF-8'
                    ) ?></strong>.
                    Manage user accounts and review their security status.
                    <br>
                    Your role:
                    <span class="role-label">
                        <?= htmlspecialchars(
                            $_SESSION['role'],
                            ENT_QUOTES,
                            'UTF-8'
                        ) ?>
                    </span>
                </p>
            </div>
        </header>

        <nav class="actions" aria-label="User management navigation">
            <a class="button" href="add-user.php">+ Add Inputer</a>
            <a class="button button-secondary"
               href="../public/dashboard.php">Back to Dashboard</a>
            <a class="button button-logout"
               href="../public/logout.php">Logout</a>
        </nav>

        <?php if ($successMessage !== ''): ?>
           <div class="notice success" role="status">
            <?= htmlspecialchars($successMessage, ENT_QUOTES, 'UTF-8') ?>
             </div>
        <?php endif; ?>

        <?php if ($errorMessage !== ''): ?>
            <div class="notice error" role="alert">
           <?= htmlspecialchars($errorMessage, ENT_QUOTES, 'UTF-8') ?>
           </div>
        <?php endif; ?>

        <section>
            <h2 class="section-heading">Registered Users</h2>
            <p class="section-description">
                View registered accounts, assigned roles, account status,
                and two-factor authentication setup.
            </p>

            <div class="table-container">
                <?php if (count($users) > 0): ?>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Username</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th>Status</th>
                                <th>2FA</th>
                                <th>Actions</th>
                            </tr>
                        </thead>

                        <tbody>
                            <?php foreach ($users as $user): ?>
                                <?php
                                $statusClass = 'status-' . strtolower(
                                    (string) $user['account_status']
                                );
                                ?>

                                <tr>
                                    <td>
                                        <?= htmlspecialchars(
                                            (string) $user['id'],
                                            ENT_QUOTES,
                                            'UTF-8'
                                        ) ?>
                                    </td>

                                    <td>
                                        <?= htmlspecialchars(
                                            $user['username'],
                                            ENT_QUOTES,
                                            'UTF-8'
                                        ) ?>
                                    </td>

                                    <td>
                                        <?= htmlspecialchars(
                                            $user['email'],
                                            ENT_QUOTES,
                                            'UTF-8'
                                        ) ?>
                                    </td>

                                    <td>
                                        <?= htmlspecialchars(
                                            $user['role_name'],
                                            ENT_QUOTES,
                                            'UTF-8'
                                        ) ?>
                                    </td>

                                    <td>
                                        <span class="status <?= htmlspecialchars(
                                            $statusClass,
                                            ENT_QUOTES,
                                            'UTF-8'
                                        ) ?>">
                                            <?= htmlspecialchars(
                                                $user['account_status'],
                                                ENT_QUOTES,
                                                'UTF-8'
                                            ) ?>
                                        </span>
                                    </td>

                                    <td>
                                        <?php if ((int) $user['two_factor_enabled'] === 1): ?>
                                            <span class="twofa-enabled">
                                                Enabled
                                            </span>
                                        <?php else: ?>
                                            <span class="twofa-disabled">
                                                Not enabled
                                            </span>
                                        <?php endif; ?>
                                    </td>

                                    
<td>
    <?php if (
        strtolower($user['role_name']) === 'inputer'
        && (int) $user['id'] !== (int) ($_SESSION['user_id'] ?? 0)
    ): ?>
        <form method="POST" action=""
              onsubmit="return confirm('Are you sure you want to remove this Inputer account? This action may be irreversible.');">

            <input
                type="hidden"
                name="csrf_token"
                value="<?= htmlspecialchars(
                    $csrfToken,
                    ENT_QUOTES,
                    'UTF-8'
                ) ?>"
            >

            <input
                type="hidden"
                name="user_id"
                value="<?= (int) $user['id'] ?>"
            >

            <button type="submit" name="remove_user"
                    class="button button-remove">
                Remove User
            </button>
        </form>
    <?php else: ?>
        <span class="protected-label">Protected</span>
    <?php endif; ?>
</td>

                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php else: ?>
                    <div class="empty-state">
                        No user accounts were found.
                    </div>
                <?php endif; ?>
            </div>
        </section>

        <footer class="page-footer">
            Save Nature· Secure User Management
        </footer>

    </main>

</body>
</html>
