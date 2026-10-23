
-- 1. List tables in the public schema
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_type = 'BASE TABLE'
ORDER BY table_name;

-- 2. List all configured roles
SELECT id, role_name
FROM roles
ORDER BY id;

-- 3. Count records in the main application tables
SELECT
    (SELECT COUNT(*) FROM users) AS users_count,
    (SELECT COUNT(*) FROM registration_requests) AS requests_count,
    (SELECT COUNT(*) FROM sessions) AS sessions_count,
    (SELECT COUNT(*) FROM audit_logs) AS audit_logs_count,
    (SELECT COUNT(*) FROM feedback) AS feedback_count;
