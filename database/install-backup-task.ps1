param(
    [string]$PhpPath = 'C:\xampp\php\php.exe',
    [string]$TaskName = 'Secure Login PostgreSQL S3 Backup',
    [string]$DailyAt = '02:00'
)

$ErrorActionPreference = 'Stop'

$backupScript = Join-Path $PSScriptRoot 'backup-to-s3.php'
$projectRoot = Split-Path -Parent $PSScriptRoot

if (-not (Test-Path -LiteralPath $PhpPath -PathType Leaf)) {
    throw "PHP executable not found: $PhpPath"
}
if (-not (Test-Path -LiteralPath $backupScript -PathType Leaf)) {
    throw "Backup script not found: $backupScript"
}
$pgDumpCommand = if ($env:PG_DUMP) {
    Get-Command $env:PG_DUMP -ErrorAction SilentlyContinue
} elseif (Test-Path -LiteralPath 'C:\Program Files\PostgreSQL\18\bin\pg_dump.exe' -PathType Leaf) {
    Get-Item -LiteralPath 'C:\Program Files\PostgreSQL\18\bin\pg_dump.exe'
} else {
    Get-Command pg_dump -ErrorAction SilentlyContinue
}
if (-not $pgDumpCommand) {
    throw 'pg_dump was not found. Add PostgreSQL bin to PATH or set PG_DUMP to its executable path.'
}
$awsCommand = if ($env:AWS_CLI) {
    Get-Command $env:AWS_CLI -ErrorAction SilentlyContinue
} elseif (Test-Path -LiteralPath 'C:\Program Files\Amazon\AWSCLIV2\aws.exe' -PathType Leaf) {
    Get-Item -LiteralPath 'C:\Program Files\Amazon\AWSCLIV2\aws.exe'
} else {
    Get-Command aws -ErrorAction SilentlyContinue
}
if (-not $awsCommand) {
    throw 'AWS CLI was not found. Install AWS CLI and configure the secure-login-backup profile.'
}

$time = [TimeSpan]::Zero
if (-not [TimeSpan]::TryParseExact($DailyAt, 'hh\:mm', [Globalization.CultureInfo]::InvariantCulture, [ref]$time)) {
    throw "Invalid daily time '$DailyAt'. Use 24-hour HH:mm format, for example 02:00."
}

$action = New-ScheduledTaskAction `
    -Execute $PhpPath `
    -Argument ('"{0}"' -f $backupScript) `
    -WorkingDirectory $projectRoot
$trigger = New-ScheduledTaskTrigger -Daily -At ([DateTime]::Today.Add($time))
$principal = New-ScheduledTaskPrincipal `
    -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType Interactive `
    -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description 'Creates an encrypted PostgreSQL dump and uploads it to the configured S3 bucket.' `
    -Force | Out-Null

Write-Output "Scheduled '$TaskName' daily at $DailyAt for $([Security.Principal.WindowsIdentity]::GetCurrent().Name)."
Write-Output 'The task runs only while that Windows user is logged on.'
