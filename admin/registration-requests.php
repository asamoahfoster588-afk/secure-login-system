
<?php
session_start();

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';

requireAdministrator();

if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = '';
$messageType = 'success';

// Handle Approve and Reject actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';

    if (
        !is_string($submittedToken) ||
        !hash_equals($_SESSION['csrf_token'], $submittedToken)
    ) {
        $message = 'Invalid security token. Please refresh the page.';
        $messageType = 'error';
    } else {
        $userId = filter_var(
            $_POST['user_id'] ?? null,
            FILTER_VALIDATE_INT
        );

        $action = $_POST['action'] ?? '';

        if (!$userId || !in_array($action, ['approve', 'reject'], true)) {
            $message = 'Invalid request. Please try again.';
            $messageType = 'error';
        } else {
            $newStatus = $action === 'approve' ? 'active' : 'inactive';

            try {
                // Only process pending Inputer accounts.
                $stmt = $pdo->prepare(
                    "UPDATE users
                     SET account_status = ?
                     WHERE id = ?
                       AND role_id = 1
                       AND account_status = 'pending'"
                );

                $stmt->execute([$newStatus, $userId]);

                if ($stmt->rowCount() === 1) {
                    $message = $action === 'approve'
                        ? 'Registration request approved successfully.'
                        : 'Registration request rejected successfully.';
                } else {
                    $message = 'This request was already processed or no longer exists.';
                    $messageType = 'error';
                }
            } catch (PDOException $e) {
                error_log('Registration review error: ' . $e->getMessage());
                $message = 'Unable to process this request. Please try again.';
                $messageType = 'error';
            }
        }
    }
}

// Fetch pending Inputer registration requests.
try {
    $stmt = $pdo->prepare(
        "SELECT id, username, email, created_at
         FROM users
         WHERE role_id = 1
           AND account_status = 'pending'
         ORDER BY created_at ASC"
    );

    $stmt->execute();
    $requests = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log('Registration requests loading error: ' . $e->getMessage());
    $requests = [];
    $message = 'Unable to load registration requests. Check the database configuration.';
    $messageType = 'error';
}
?><?php

session_start();

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';

requireAdministrator();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = '';
$messageType = 'success';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = $_POST['csrf_token'] ?? '';

    if (
        !is_string($submittedToken) ||
        !hash_equals($_SESSION['csrf_token'], $submittedToken)
    ) {
        $message = 'Invalid security token. Please refresh the page.';
        $messageType = 'error';

    } else {
        $requestId = filter_var(
            $_POST['user_id'] ?? null,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 1]]
        );

        $action = $_POST['action'] ?? '';

        if (
            $requestId === false ||
            $requestId === null ||
            !in_array($action, ['approve', 'reject'], true)
        ) {
            $message = 'Invalid request. Please try again.';
            $messageType = 'error';

        } else {
            try {
                $adminId = filter_var(
                    $_SESSION['user_id'] ?? null,
                    FILTER_VALIDATE_INT,
                    ['options' => ['min_range' => 1]]
                );

                if ($adminId === false || $adminId === null) {
                    throw new RuntimeException(
                        'Administrator session is invalid.'
                    );
                }

                $pdo->beginTransaction();

                // Lock the application to prevent concurrent reviews.
                $stmt = $pdo->prepare(
                    "SELECT
                        rr.id,
                        rr.username,
                        rr.email,
                        rr.password_hash,
                        rr.requested_role_id,
                        rr.request_status,
                        r.role_name
                     FROM registration_requests rr
                     INNER JOIN roles r
                        ON r.id = rr.requested_role_id
                     WHERE rr.id = :request_id
                     FOR UPDATE OF rr"
                );

                $stmt->execute([
                    'request_id' => $requestId
                ]);

                $request = $stmt->fetch(PDO::FETCH_ASSOC);

                if (!$request || $request['request_status'] !== 'pending') {
                    throw new DomainException(
                        'This request has already been processed or no longer exists.'
                    );
                }

                // Only Inputer applications can be reviewed here.
                if ($request['role_name'] !== 'inputer') {
                    throw new DomainException(
                        'This page can only process Inputer registration requests.'
                    );
                }

                if ($action === 'approve') {
                    // Create the active user account.
                    $insertUser = $pdo->prepare(
                        "INSERT INTO users (
                            username,
                            email,
                            password_hash,
                            role_id,
                            account_status
                        )
                        VALUES (
                            :username,
                            :email,
                            :password_hash,
                            :role_id,
                            'active'
                        )"
                    );

                    $insertUser->execute([
                        'username' => $request['username'],
                        'email' => $request['email'],
                        'password_hash' => $request['password_hash'],
                        'role_id' => $request['requested_role_id']
                    ]);

                    $newStatus = 'approved';

                } else {
                    $newStatus = 'rejected';
                }

                // Record the administrator's decision.
                $updateRequest = $pdo->prepare(
                    "UPDATE registration_requests
                     SET request_status = :status,
                         reviewed_by = :admin_id,
                         reviewed_at = CURRENT_TIMESTAMP
                     WHERE id = :request_id
                       AND request_status = 'pending'"
                );

                $updateRequest->execute([
                    'status' => $newStatus,
                    'admin_id' => $adminId,
                    'request_id' => $requestId
                ]);

                if ($updateRequest->rowCount() !== 1) {
                    throw new RuntimeException(
                        'The registration request could not be updated.'
                    );
                }

                $pdo->commit();

                $message = $action === 'approve'
                    ? 'Registration request approved successfully. The user can now log in and complete 2FA enrollment.'
                    : 'Registration request rejected successfully.';

            } catch (DomainException $e) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                $message = $e->getMessage();
                $messageType = 'error';

            } catch (Throwable $e) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                error_log(
                    'Registration review error: ' . $e->getMessage()
                );

                $message = 'Unable to process this request. '
                    . 'Check the application logs if the problem continues.';
                $messageType = 'error';
            }
        }
    }
}

// Fetch pending Inputer applications.
try {
    $stmt = $pdo->prepare(
        "SELECT
            rr.id,
            rr.username,
            rr.email,
            rr.requested_at,
            rr.request_status
         FROM registration_requests rr
         INNER JOIN roles r
            ON r.id = rr.requested_role_id
         WHERE r.role_name = :role_name
           AND rr.request_status = 'pending'
         ORDER BY rr.requested_at ASC"
    );

    $stmt->execute([
        'role_name' => 'inputer'
    ]);

    $requests = $stmt->fetchAll(PDO::FETCH_ASSOC);

} catch (PDOException $e) {
    error_log(
        'Registration requests loading error: ' . $e->getMessage()
    );

    $requests = [];
    $message = 'Unable to load registration requests. Please check the database configuration.';
    $messageType = 'error';
}
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Requests | Secure Login</title>

    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            min-height: 100vh;
            padding: 35px 18px;
            font-family: Arial, Helvetica, sans-serif;
            color: #23332b;
            background:
                linear-gradient(rgba(8, 35, 25, 0.72),
                                rgba(8, 35, 25, 0.78)),
                url('https://images.unsplash.com/photo-1448375240586-882707db888b?auto=format&fit=crop&w=2000&q=85')
                center / cover fixed;
        }

        .container {
            width: 100%;
            max-width: 1150px;
            margin: 0 auto;
        }

        .brand {
            text-align: center;
            color: #fff;
            margin-bottom: 25px;
        }

        .brand h1 {
            font-size: 30px;
            letter-spacing: 2px;
            margin-bottom: 8px;
        }

        .brand p {
            color: #e0f0e5;
            font-size: 14px;
        }

        .panel {
            background: #fff;
            border-radius: 16px;
            padding: 30px;
            box-shadow: 0 15px 45px rgba(0, 0, 0, 0.25);
        }

        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 15px;
            flex-wrap: wrap;
            margin-bottom: 25px;
        }

        .panel-header h2 {
            color: #205c3b;
            font-size: 25px;
            margin-bottom: 7px;
        }

        .panel-header p {
            color: #68766d;
            font-size: 14px;
        }

        .count {
            display: inline-block;
            padding: 10px 15px;
            background: #e8f4eb;
            color: #205c3b;
            border-radius: 9px;
            font-weight: bold;
        }

        .alert {
            padding: 13px 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
        }

        .alert.success {
            color: #205c3b;
            background: #e8f4eb;
            border: 1px solid #b8dfc3;
        }

        .alert.error {
            color: #922d2d;
            background: #fdecec;
            border: 1px solid #f3c1c1;
        }

        .table-wrapper {
            width: 100%;
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 700px;
        }

        th, td {
            padding: 16px 13px;
            text-align: left;
            border-bottom: 1px solid #e5ebe6;
            vertical-align: middle;
        }

        th {
            background: #f1f6f2;
            color: #285b3e;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.6px;
        }

        td {
            font-size: 14px;
        }

        tbody tr:hover {
            background: #fafcfb;
        }

        .status {
            display: inline-block;
            padding: 6px 10px;
            background: #fff3d8;
            color: #825b0b;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }

        .actions {
            display: flex;
            gap: 8px;
            align-items: center;
        }

        .actions form {
            margin: 0;
        }

        button, .button {
            display: inline-block;
            padding: 9px 13px;
            border: none;
            border-radius: 7px;
            color: #fff;
            font-size: 13px;
            font-weight: bold;
            cursor: pointer;
            text-decoration: none;
            transition: opacity 0.2s;
        }

        button:hover, .button:hover {
            opacity: 0.85;
        }

        .approve {
            background: #267447;
        }

        .reject {
            background: #b83a3a;
        }

        .secondary {
            background: #35483d;
        }

        .empty {
            padding: 45px 15px;
            text-align: center;
            color: #68766d;
        }

        .empty h3 {
            color: #285b3e;
            margin-bottom: 10px;
        }

        .footer-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #e5ebe6;
        }

        @media (max-width: 600px) {
            body {
                padding: 20px 10px;
            }

            .panel {
                padding: 20px 14px;
            }

            .brand h1 {
                font-size: 24px;
            }

            .panel-header h2 {
                font-size: 21px;
            }
        }
    </style>
</head>

<body>
<div class="container">

    <header class="brand">
        <h1>SECURE LOGIN SYSTEM</h1>
        <p>Account Registration and Access Management</p>
    </header>

    <main class="panel">
        <div class="panel-header">
            <div>
                <h2>Registration Requests</h2>
                <p>Review and manage requests for Inputer accounts.</p>
            </div>

            <div class="count">
                Pending: <?= count($requests) ?>
            </div>
        </div>

        <?php if ($message !== ''): ?>
            <div class="alert <?= htmlspecialchars($messageType, ENT_QUOTES, 'UTF-8') ?>" role="status">
                <?= htmlspecialchars($message) ?>
            </div>
        <?php endif; ?>

        <?php if (count($requests) > 0): ?>
            <div class="table-wrapper">
                <table>
                    <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email Address</th>
                        <th>Request Date</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                    </thead>

                    <tbody>
                    <?php foreach ($requests as $request): ?>
                        <tr>
                            <td>
                                <?= htmlspecialchars($request['username']) ?>
                            </td>

                            <td>
                                <?= htmlspecialchars($request['email']) ?>
                            </td>

                            <td>
                                <?= htmlspecialchars(
                                    $request['requested_at'] ?? 'Not available'
                                ) ?>
                            </td>

                            <td>
                                <span class="status">Pending</span>
                            </td>

                            <td>
                                <div class="actions">
                                    <form method="POST"
                                          onsubmit="return confirm('Approve this registration request?');">
                                        <input type="hidden"
                                               name="csrf_token"
                                               value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

                                        <input type="hidden"
                                               name="user_id"
                                               value="<?= (int) $request['id'] ?>">

                                        <input type="hidden"
                                               name="action"
                                               value="approve">

                                        <button type="submit" class="approve">
                                            Approve
                                        </button>
                                    </form>

                                    <form method="POST"
                                          onsubmit="return confirm('Reject this registration request?');">
                                        <input type="hidden"
                                               name="csrf_token"
                                               value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

                                        <input type="hidden"
                                               name="user_id"
                                               value="<?= (int) $request['id'] ?>">

                                        <input type="hidden"
                                               name="action"
                                               value="reject">

                                        <button type="submit" class="reject">
                                            Reject
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php else: ?>
            <div class="empty">
                <h3>No Pending Requests</h3>
                <p>There are currently no Inputer registration requests awaiting review.</p>
            </div>
        <?php endif; ?>

        <div class="footer-actions">
            <a href="users.php" class="button secondary">
                User Management
            </a>

            <a href="../public/dashboard.php" class="button secondary">
                Dashboard
            </a>

            <a href="../public/logout.php" class="button secondary">
                Logout
            </a>
        </div>
    </main>
</div>
</body>
</html>
