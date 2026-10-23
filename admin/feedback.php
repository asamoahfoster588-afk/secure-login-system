
<?php
session_start();

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../config/database.php';

requireLogin();

$role = $_SESSION['role'] ?? '';

if (!in_array(
    $role,
    ['administrator', 'reviewer', 'auditor'],
    true
)) {
    http_response_code(403);
    exit('Access denied.');
}

$isAdministrator = ($role === 'administrator');

if (empty($_SESSION['feedback_admin_csrf'])) {
    $_SESSION['feedback_admin_csrf'] = bin2hex(random_bytes(32));
}

$csrfToken = $_SESSION['feedback_admin_csrf'];
$success = $_SESSION['feedback_admin_success'] ?? '';
$error = '';

unset($_SESSION['feedback_admin_success']);

// Handle administrator actions.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$isAdministrator) {
        http_response_code(403);
        exit('Access denied.');
    }

    $token = $_POST['csrf_token'] ?? '';
    $action = $_POST['action'] ?? '';
    $feedbackId = filter_input(
        INPUT_POST,
        'feedback_id',
        FILTER_VALIDATE_INT
    );

    if (
        !is_string($token) ||
        !hash_equals($csrfToken, $token)
    ) {
        $error = 'Invalid security token. Refresh the page and try again.';
    } elseif (!$feedbackId || $feedbackId < 1) {
        $error = 'Invalid feedback record.';
    } else {
        try {
            if ($action === 'delete') {
                $stmt = $pdo->prepare(
                    'DELETE FROM feedback WHERE id = :id'
                );
                $stmt->execute([':id' => $feedbackId]);

                $_SESSION['feedback_admin_success'] =
                    $stmt->rowCount() > 0
                    ? 'Feedback deleted successfully.'
                    : 'Feedback was not found or was already deleted.';

            } elseif ($action === 'review') {
                $stmt = $pdo->prepare(
                    "UPDATE feedback
                     SET feedback_status = 'reviewed',
                         reviewed_at = CURRENT_TIMESTAMP
                     WHERE id = :id AND feedback_status = 'open'"
                );
                $stmt->execute([':id' => $feedbackId]);

                $_SESSION['feedback_admin_success'] =
                    $stmt->rowCount() > 0
                    ? 'Feedback marked as reviewed.'
                    : 'No open feedback was changed.';

            } elseif ($action === 'respond') {
                $response = trim($_POST['admin_response'] ?? '');

                if (
                    !is_string($response) ||
                    $response === '' ||
                    strlen($response) > 5000
                ) {
                    $error = 'Enter a response of no more than 5000 bytes.';
                } else {
                    $stmt = $pdo->prepare(
                        "UPDATE feedback
                         SET admin_response = :response,
                             feedback_status = 'resolved',
                             reviewed_at = CURRENT_TIMESTAMP
                         WHERE id = :id"
                    );

                    $stmt->execute([
                        ':response' => $response,
                        ':id' => $feedbackId
                    ]);

                    $_SESSION['feedback_admin_success'] =
                        $stmt->rowCount() > 0
                        ? 'Your response has been saved.'
                        : 'Feedback was not found or the response was unchanged.';
                }
            } else {
                $error = 'Unknown action requested.';
            }

            if ($error === '') {
                header('Location: ' . $_SERVER['PHP_SELF']);
                exit;
            }
        } catch (PDOException $e) {
            error_log('Administrator feedback action failed: ' . $e->getMessage());
            $error = 'The action could not be completed. Please try again.';
        }
    }
}

// Retrieve all feedback and the sender's username.
try {
    $stmt = $pdo->query(
        "SELECT
            feedback.id,
            feedback.user_id,
            feedback.category,
            feedback.subject,
            feedback.message,
            feedback.feedback_status,
            feedback.admin_response,
            feedback.created_at,
            feedback.reviewed_at,
            users.username
         FROM feedback
         LEFT JOIN users ON users.id = feedback.user_id
         ORDER BY
            CASE feedback.feedback_status
                WHEN 'open' THEN 0
                WHEN 'reviewed' THEN 1
                ELSE 2
            END,
            feedback.created_at DESC"
    );

    $feedbackList = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log('Feedback retrieval failed: ' . $e->getMessage());
    $feedbackList = [];
    $error = 'Feedback could not be loaded. Check the database configuration.';
}

function feedbackEscape($value): string
{
    return htmlspecialchars(
        (string) ($value ?? ''),
        ENT_QUOTES,
        'UTF-8'
    );
}

$openCount = 0;
foreach ($feedbackList as $item) {
    if ($item['feedback_status'] === 'open') {
        $openCount++;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Feedback Management | Secure Login System</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            padding: 30px 18px;
            background: #edf2eb;
            color: #24352a;
            font-family: Arial, Helvetica, sans-serif;
        }

        .page {
            max-width: 1100px;
            margin: 0 auto;
        }

        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
            margin-bottom: 26px;
        }

        .topbar h1 {
            margin: 0 0 7px;
            color: #173f2b;
            font-size: clamp(24px, 4vw, 32px);
        }

        .topbar p {
            margin: 0;
            color: #69766d;
            line-height: 1.6;
        }

        .button,
        button {
            display: inline-block;
            padding: 11px 15px;
            border: 0;
            border-radius: 8px;
            background: #173f2b;
            color: #fff;
            font-size: 14px;
            font-weight: 700;
            text-decoration: none;
            cursor: pointer;
        }

        .button:hover,
        button:hover {
            background: #245b3b;
        }

        .summary {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 15px;
            flex-wrap: wrap;
            margin-bottom: 22px;
            padding: 20px;
            border: 1px solid #dce5d9;
            border-left: 5px solid #d9b45b;
            border-radius: 12px;
            background: #fff;
        }

        .summary strong {
            color: #173f2b;
            font-size: 18px;
        }

        .summary span {
            color: #69766d;
            font-size: 14px;
        }

        .feedback-card {
            margin-bottom: 22px;
            padding: 24px;
            border: 1px solid #dce5d9;
            border-radius: 12px;
            background: #fff;
            box-shadow: 0 5px 18px rgba(16, 44, 30, .05);
        }

        .feedback-card h2 {
            margin: 0 0 14px;
            color: #173f2b;
            overflow-wrap: anywhere;
        }

        .meta {
            display: flex;
            flex-wrap: wrap;
            gap: 8px 18px;
            margin-bottom: 18px;
            color: #69766d;
            font-size: 13px;
        }

        .status {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            background: #f4ecd5;
            color: #76591b;
            font-size: 12px;
            font-weight: 700;
        }

        .status.reviewed {
            background: #e4eee6;
            color: #245b3b;
        }

        .status.resolved {
            background: #e7edfa;
            color: #294c85;
        }

        .message {
            margin: 0 0 20px;
            line-height: 1.8;
            overflow-wrap: anywhere;
            white-space: pre-wrap;
        }

        .response-box {
            margin: 18px 0;
            padding: 16px;
            border-left: 4px solid #d9b45b;
            border-radius: 7px;
            background: #f8f7f0;
        }

        .response-box strong {
            display: block;
            margin-bottom: 8px;
            color: #173f2b;
        }

        .response-box p {
            margin: 0;
            line-height: 1.7;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
        }

        .field-label {
            display: block;
            margin: 18px 0 8px;
            color: #24352a;
            font-size: 14px;
            font-weight: 700;
        }

        textarea {
            display: block;
            width: 100%;
            min-height: 105px;
            padding: 12px;
            border: 1px solid #cbd6ca;
            border-radius: 8px;
            background: #fcfdfb;
            color: #24352a;
            font: inherit;
            line-height: 1.6;
            resize: vertical;
        }

        textarea:focus {
            outline: none;
            border-color: #245b3b;
            box-shadow: 0 0 0 3px rgba(36, 91, 59, .12);
        }

        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 15px;
        }

        .delete-button {
            background: #fff;
            border: 1px solid #b42318;
            color: #b42318;
        }

        .delete-button:hover {
            background: #b42318;
            color: #fff;
        }

        .notice {
            margin-bottom: 20px;
            padding: 14px 16px;
            border-radius: 8px;
            line-height: 1.6;
        }

        .success {
            background: #e8f5e9;
            border: 1px solid #c6e5ca;
            color: #205b2b;
        }

        .error {
            background: #fff0ef;
            border: 1px solid #f2cfcc;
            color: #a52d2d;
        }

        .empty {
            padding: 40px 20px;
            border: 1px dashed #cbd6ca;
            border-radius: 12px;
            background: #fff;
            text-align: center;
            color: #69766d;
            line-height: 1.7;
        }

        footer {
            margin-top: 32px;
            padding: 20px 0;
            border-top: 1px solid #d4ded2;
            color: #69766d;
            font-size: 13px;
            line-height: 1.7;
            text-align: center;
        }

        @media (max-width: 600px) {
            body {
                padding: 20px 12px;
            }

            .feedback-card {
                padding: 18px;
            }

            .topbar .button {
                width: 100%;
                text-align: center;
            }
        }
    </style>
</head>
<body>
<div class="page">

    <header class="topbar">
        <div>
            <h1>Feedback Management</h1>
            <p>Review messages and respond to Inputer feedback.</p>
        </div>

        <a class="button" href="../public/dashboard.php">
            Back to Dashboard
        </a>
    </header>

    <?php if ($success !== ''): ?>
        <div class="notice success" role="status">
            <?= feedbackEscape($success) ?>
        </div>
    <?php endif; ?>

    <?php if ($error !== ''): ?>
        <div class="notice error" role="alert">
            <?= feedbackEscape($error) ?>
        </div>
    <?php endif; ?>

    <section class="summary">
        <strong><?= count($feedbackList) ?> feedback message(s)</strong>
        <span><?= $openCount ?> awaiting review</span>
    </section>

    <?php if (empty($feedbackList)): ?>
        <div class="empty">
            <h2>No feedback yet</h2>
            <p>Messages submitted by Inputers will appear here.</p>
        </div>
    <?php else: ?>

        <?php foreach ($feedbackList as $feedback): ?>
            <article class="feedback-card">
                <div class="meta">
                    <span>
                        From:
                        <strong><?= feedbackEscape(
                            $feedback['username'] ?? 'Deleted or unknown user'
                        ) ?></strong>
                    </span>

                    <span>
                        Category: <?= feedbackEscape($feedback['category']) ?>
                    </span>

                    <span>
                        Submitted:
                        <?= feedbackEscape($feedback['created_at']) ?>
                    </span>

                    <span class="status <?= feedbackEscape($feedback['feedback_status']) ?>">
                        <?= feedbackEscape(ucfirst($feedback['feedback_status'])) ?>
                    </span>
                </div>

                <h2><?= feedbackEscape($feedback['subject']) ?></h2>

                <p class="message"><?= feedbackEscape($feedback['message']) ?></p>

                <?php if (!empty($feedback['admin_response'])): ?>
                    <div class="response-box">
                        <strong>Administrator response</strong>
                        <p><?= feedbackEscape($feedback['admin_response']) ?></p>
                    </div>
                <?php endif; ?>

                <?php if ($isAdministrator): ?>
                    <form method="POST" action="">
                        <input type="hidden" name="csrf_token"
                               value="<?= feedbackEscape($csrfToken) ?>">
                        <input type="hidden" name="feedback_id"
                               value="<?= (int) $feedback['id'] ?>">
                        <input type="hidden" name="action" value="respond">

                        <label class="field-label"
                               for="response-<?= (int) $feedback['id'] ?>">
                            Write or update response
                        </label>

                        <textarea
                            id="response-<?= (int) $feedback['id'] ?>"
                            name="admin_response"
                            maxlength="5000"
                            required
                            placeholder="Write a response to this feedback..."
                        ><?= feedbackEscape($feedback['admin_response'] ?? '') ?></textarea>

                        <div class="actions">
                            <button type="submit">Save Response</button>
                        </div>
                    </form>

                    <div class="actions">
                        <?php if ($feedback['feedback_status'] === 'open'): ?>
                            <form method="POST" action="">
                                <input type="hidden" name="csrf_token"
                                       value="<?= feedbackEscape($csrfToken) ?>">
                                <input type="hidden" name="feedback_id"
                                       value="<?= (int) $feedback['id'] ?>">
                                <input type="hidden" name="action" value="review">
                                <button type="submit">Mark as Reviewed</button>
                            </form>
                        <?php endif; ?>

                        <form method="POST" action=""
                              onsubmit="return confirm('Permanently delete this feedback? This cannot be undone.');">
                            <input type="hidden" name="csrf_token"
                                   value="<?= feedbackEscape($csrfToken) ?>">
                            <input type="hidden" name="feedback_id"
                                   value="<?= (int) $feedback['id'] ?>">
                            <input type="hidden" name="action" value="delete">
                            <button type="submit" class="delete-button">
                                Delete Feedback
                            </button>
                        </form>
                    </div>
                <?php endif; ?>
            </article>
        <?php endforeach; ?>

    <?php endif; ?>

    <footer>
        <strong>Secure Login System</strong>
        <p>Administrator Feedback Management</p>
    </footer>

</div>
</body>
</html>
