<?php

require_once '../config/database.php';

$secrets = require '../config/secrets.php';

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username === '' || $email === '' || $password === '') {
        $message = 'All fields are required.';
    } elseif (strlen($password) < 12) {
        $message = 'Password must be at least 12 characters.';
    } else {

        // Add the server-side pepper.
        $passwordWithPepper =
            $password . $secrets['password_pepper'];

        // Hash using Argon2id.
        $passwordHash = password_hash(
            $passwordWithPepper,
            PASSWORD_ARGON2ID
        );

        // Administrator role = 4
        $roleId = 4;

        try {

            $stmt = $pdo->prepare(
                "INSERT INTO users
                (username, email, password_hash, role_id)
                VALUES (?, ?, ?, ?)"
            );

            $stmt->execute([
                $username,
                $email,
                $passwordHash,
                $roleId
            ]);

            $message = 'Administrator account created successfully.';

        } catch (PDOException $e) {

            $message = 'Unable to create account.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Create Administrator</title>
</head>

<body>

<h1>Create Administrator</h1>

<?php if ($message): ?>
    <p><?= htmlspecialchars($message) ?></p>
<?php endif; ?>

<form method="POST">

    <label>Username</label><br>
    <input type="text" name="username" required>
    <br><br>

    <label>Email</label><br>
    <input type="email" name="email" required>
    <br><br>

    <label>Password</label><br>
    <input type="password" name="password" required>
    <br><br>

    <button type="submit">
        Create Administrator
    </button>

</form>

</body>
</html>