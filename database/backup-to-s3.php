<?php

declare(strict_types=1);

function runCommand(array $command, string $outputPath, string $label): void
{
    $descriptors = [
        0 => ['file', 'NUL', 'r'],
        1 => ['file', $outputPath, 'a'],
        2 => ['file', $outputPath, 'a'],
    ];

    $process = proc_open($command, $descriptors, $pipes);
    if (!is_resource($process)) {
        throw new RuntimeException("Unable to start $label.");
    }

    $exitCode = proc_close($process);
    if ($exitCode !== 0) {
        $output = trim((string) file_get_contents($outputPath));
        throw new RuntimeException(
            $output === '' ? "$label failed with exit code $exitCode." : "$label failed: $output"
        );
    }
}

$databaseConfig = __DIR__ . '/../config/database.php';
$temporaryDump = tempnam(sys_get_temp_dir(), 'secure_login_backup_');
if ($temporaryDump === false) {
    throw new RuntimeException('Unable to create a temporary database dump file.');
}

$temporaryLog = tempnam(sys_get_temp_dir(), 'secure_login_backup_log_');
if ($temporaryLog === false) {
    @unlink($temporaryDump);
    throw new RuntimeException('Unable to create a temporary command log file.');
}

$dumpPath = $temporaryDump . '.dump';
if (!rename($temporaryDump, $dumpPath)) {
    @unlink($temporaryDump);
    @unlink($temporaryLog);
    throw new RuntimeException('Unable to prepare the temporary database dump.');
}

$cleanup = static function () use ($dumpPath, $temporaryLog): void {
    @unlink($dumpPath);
    @unlink($temporaryLog);
};
register_shutdown_function($cleanup);

$exitCode = 0;
try {
    require $databaseConfig;

    if (!isset($host, $port, $dbname, $username, $password) || $password === '') {
        throw new RuntimeException('The database configuration is incomplete.');
    }

    $pgDump = getenv('PG_DUMP') ?: 'C:\\Program Files\\PostgreSQL\\18\\bin\\pg_dump.exe';
    $awsCli = getenv('AWS_CLI') ?: 'C:\\Program Files\\Amazon\\AWSCLIV2\\aws.exe';
    if (!is_file($pgDump)) {
        $pgDump = getenv('PG_DUMP') ?: 'pg_dump';
    }
    if (!is_file($awsCli)) {
        $awsCli = getenv('AWS_CLI') ?: 'aws';
    }
    $awsProfile = getenv('AWS_PROFILE') ?: 'secure-login-backup';
   $timestamp = gmdate('Ymd\THis\Z');
$objectKey = "postgres/secure_login_db_$timestamp.dump";
$s3Uri = "s3://secure---login-190865906277-eu-north-1-an/$objectKey";

    putenv('PGPASSWORD=' . $password);
    try {
        runCommand([
            $pgDump,
            '--host', $host,
            '--port', (string) $port,
            '--username', $username,
            '--dbname', $dbname,
            '--format=custom',
            '--no-password',
            '--file=' . $dumpPath,
        ], $temporaryLog, 'pg_dump');
    } finally {
        putenv('PGPASSWORD');
    }

    runCommand([
        $awsCli,
        's3', 'cp',
        $dumpPath,
        $s3Uri,
        '--profile', $awsProfile,
        '--sse', 'AES256',
        '--only-show-errors',
    ], $temporaryLog, 'AWS S3 upload');

    fwrite(STDOUT, "Database backup uploaded to $s3Uri\n");
} catch (Throwable $error) {
    fwrite(STDERR, "Database backup failed: {$error->getMessage()}\n");
    $exitCode = 1;
} finally {
    $cleanup();
}

exit($exitCode);
