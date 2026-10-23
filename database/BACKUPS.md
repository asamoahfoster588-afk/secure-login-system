# Automated PostgreSQL Backups

`backup-to-s3.php` creates a PostgreSQL custom-format dump using the database settings in `config/database.php`, then uploads it with server-side AES-256 encryption to:

`s3://secure---login-190865906277-eu-north-1-an/postgres/`

Temporary dump files are removed after the upload attempt.

## One-time setup

1. Install AWS CLI and PostgreSQL client tools. Ensure `aws` and `pg_dump` are available to the Windows account that runs the backup.

2. Configure the AWS CLI profile named `secure-login-backup`:

   ```powershell
   aws configure --profile secure-login-backup
   ```

   Use credentials with only the permissions required for the intended S3 backup operations. Configure the profile for the `eu-north-1` region. Do not put AWS access keys in this project or commit them to source control.

3. To install a daily scheduled task at 02:00, open PowerShell and run:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   & 'C:\xampp\htdocs\secure_login\database\install-backup-task.ps1'
   ```

   **Warning:** This command registers or replaces a scheduled task with the configured task name. Do not run it if you already have a working backup task you want to preserve.

   To select another time, pass `-DailyAt 'HH:mm'`. To use another PHP executable, pass `-PhpPath`.

## Manual run and troubleshooting

To run a backup manually:

```powershell
& 'C:\xampp\php\php.exe' 'C:\xampp\htdocs\secure_login\database\backup-to-s3.php'
```

The script reports failures to standard error and exits with a nonzero status. Review the Task Scheduler history and logs when troubleshooting scheduled runs.

The environment variables `AWS_PROFILE`, `AWS_CLI`, and `PG_DUMP` can override the corresponding defaults when required.

## Security notes

- Keep database credentials in local configuration or environment variables, never in Git.
- Do not commit AWS credentials, database dumps, or backup exports.
- Test backup restoration periodically; a successful upload alone does not prove a backup can be restored.