
INSERT INTO roles (role_name)
VALUES
    ('administrator'),
    ('inputer'),
    ('reviewer'),
    ('auditor')
ON CONFLICT (role_name) DO NOTHING;

SELECT id, role_name
FROM roles
ORDER BY id;
