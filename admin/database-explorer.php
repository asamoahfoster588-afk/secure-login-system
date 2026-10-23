<?php
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

require_once __DIR__ . '/../includes/auth.php';
requireAdministrator();

require_once __DIR__ . '/../config/database.php';
$secrets = require __DIR__ . '/../config/secrets.php';

function e($value): string
{
    return htmlspecialchars(
        (string) $value,
        ENT_QUOTES,
        'UTF-8'
    );
}

// Find all tables in the application's public schema.
$tableStmt = $pdo->query("
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = 'public'
      AND table_type = 'BASE TABLE'
    ORDER BY table_name
");

$tables = $tableStmt->fetchAll(PDO::FETCH_COLUMN);

$selectedTable = $_GET['table'] ?? '';
$columns = [];
$rows = [];
$error = '';

if ($selectedTable !== '') {
    // Only allow tables actually found in the public schema.
    if (!in_array($selectedTable, $tables, true)) {
        http_response_code(400);
        $error = 'Invalid table selection.';
    } else {
        $columnStmt = $pdo->prepare("
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = :table
            ORDER BY ordinal_position
        ");

        $columnStmt->execute(['table' => $selectedTable]);
        $columns = $columnStmt->fetchAll(PDO::FETCH_ASSOC);

        // Keep authentication secrets hidden.
// Only the stored password hash in the users table is exposed
// to this administrator-only Database Explorer.
$hiddenColumns = [
    'password',
    'password_pepper',
    'two_factor_secret',
    'secret',
    'token',
    'session_token'
];

// Hide password_hash in every table except users.
if ($selectedTable !== 'users') {
    $hiddenColumns[] = 'password_hash';
}

$visibleColumns = array_values(array_filter(
    $columns,
    fn($column) =>
        !in_array(
            strtolower($column['column_name']),
            $hiddenColumns,
            true
        )
));

// Hide credential and authentication-secret columns.
       $hiddenColumns = [
    'password',
    'password_pepper',
    'two_factor_secret',
    'secret',
    'token',
    'session_token'
];

if ($selectedTable !== 'users') {
    $hiddenColumns[] = 'password_hash';
}

$visibleColumns = array_values(array_filter(
    $columns,
    fn($column) =>
        !in_array(
            strtolower($column['column_name']),
            $hiddenColumns,
            true
        )
));
        if ($visibleColumns) {
            $columnNames = array_map(
                fn($column) =>
                    '"' . str_replace(
                        '"',
                        '""',
                        $column['column_name']
                    ) . '"',
                $visibleColumns
            );

            $quotedTable = '"' . str_replace(
                '"',
                '""',
                $selectedTable
            ) . '"';

            $sql = 'SELECT '
                . implode(', ', $columnNames)
                . ' FROM public.'
                . $quotedTable
                . ' LIMIT 100';

           $rows = $pdo->query($sql)->fetchAll(PDO::FETCH_ASSOC);

// Extract the encoded salt from each Argon2id hash.
// The salt is already embedded in PHP's password_hash() output.
if (
    $selectedTable === 'users'
    && in_array('password_hash', array_column($visibleColumns, 'column_name'), true)
) {
    foreach ($rows as &$row) {
        $hash = (string) ($row['password_hash'] ?? '');
        $parts = explode('$', $hash);

        $salt = 'Unavailable / unsupported hash format';

        if (
            count($parts) === 6
            && $parts[1] === 'argon2id'
            && $parts[4] !== ''
        ) {
            $salt = $parts[4];
        }

        $row['salt_encoded'] = $salt;
        $row['Pepper'] = isset($secrets['password_pepper'])
            && is_string($secrets['password_pepper'])
            && $secrets['password_pepper'] !== ''
                ? 'Configured (hidden)'
                : 'Not configured';
    }

    unset($row);
}
        }
    }
}


?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1">

    <title>Database Explorer</title>

    <style>
        body {
            margin: 0;
            padding: 25px;
            font-family: Arial, sans-serif;
            background: #f2f5f9;
            color: #202938;
        }

        .container {
            max-width: 1200px;
            margin: auto;
        }

        .panel {
            background: white;
            padding: 22px;
            margin-bottom: 22px;
            border-radius: 10px;
            box-shadow: 0 3px 12px #0000000d;
        }

        h1, h2 {
            color: #174b83;
        }

        a, button {
            display: inline-block;
            padding: 10px 14px;
            background: #174b83;
            color: white;
            text-decoration: none;
            border: 0;
            border-radius: 5px;
            cursor: pointer;
        }

        select {
            padding: 10px;
            max-width: 100%;
        }

        .tables {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }

        .table-wrap {
            overflow-x: auto;
        }

        table {
            border-collapse: collapse;
            width: 100%;
            margin-top: 15px;
        }

        th, td {
            padding: 11px;
            border: 1px solid #dce2e9;
            text-align: left;
        }

        th {
            background: #174b83;
            color: white;
        }

        pre {
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            background: #17212f;
            color: #e8f0fa;
            padding: 18px;
            border-radius: 8px;
            overflow-x: auto;
        }

        .note {
            color: #555;
        }
    </style>
</head>
<body>
<div class="container">

    <div class="panel">
        <h1>Database Explorer</h1>
        <p>Inspect database tables, structures and records.</p>
        <a href="../public/dashboard.php">Back to Dashboard</a>
    </div>

    <div class="panel">
        <h2>Database Tables</h2>

        <?php if (!$tables): ?>
            <p>No tables found in the public schema.</p>
        <?php else: ?>
            <div class="tables">
                <?php foreach ($tables as $table): ?>
                    <a href="?table=<?= urlencode($table) ?>">
                        <?= e($table) ?>
                    </a>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>

    <?php if ($error !== ''): ?>
        <div class="panel">
            <p><?= e($error) ?></p>
        </div>
    <?php elseif ($selectedTable !== ''): ?>
        <div class="panel">
            <h2>Table: <?= e($selectedTable) ?></h2>

            <h3>Table Structure</h3>
            <div class="table-wrap">
                <table>
                    <thead>
                    <tr>
                        <th>Column</th>
                        <th>Data Type</th>
                        <th>Nullable</th>
                    </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($columns as $column): ?>
                        <tr>
                            <td><?= e($column['column_name']) ?></td>
                            <td><?= e($column['data_type']) ?></td>
                            <td><?= e($column['is_nullable']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <h3>Records (maximum 100)</h3>
            <p class="note">
              The stored password hash and its encoded salt are visible here
              for administrator inspection. The pepper and other authentication
              secrets remain hidden. Treat password hashes as sensitive data.
            </p>

            <?php if (!$rows): ?>
                <p>No visible records found.</p>
            <?php else: ?>
                <div class="table-wrap">
                    <table>
                        <thead>
                        <tr>
                            <?php foreach (array_keys($rows[0]) as $key): ?>
                                <th><?= e($key) ?></th>
                            <?php endforeach; ?>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($rows as $row): ?>
                            <tr>
                                <?php foreach ($row as $value): ?>
                                    <td><?= e($value ?? 'NULL') ?></td>
                                <?php endforeach; ?>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <div class="panel">
        <h2>Password Hashing Code</h2>
        <p>
            Example of the Argon2id hashing approach used in your
            application. Confirm it matches your actual login and
            registration files.
        </p>

<pre><code>// Hash a password during account creation
$hash = password_hash(
    $password . $secrets['password_pepper'],
    PASSWORD_ARGON2ID
);

// Verify a password during login
$isValid = password_verify(
    $password . $secrets['password_pepper'],
    $user['password_hash']
);</code></pre>

    <p class="note">
       The pepper is stored separately in server-side configuration and
      is never displayed by the Database Explorer. The salt is generated
      by PHP and encoded within the password hash. This example illustrates
      the hashing approach; it does not retrieve the actual pepper value.
    </p>
    </div>

</div>
</body>
</html>