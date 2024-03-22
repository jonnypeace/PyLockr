-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';
FLUSH PRIVILEGES;

-- Disable remote root access
-- This step is usually not needed if you haven't manually created remote root users,
-- as by default, root access is local. Adjustments are shown here for completeness.
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
FLUSH PRIVILEGES;

-- Remove test database and access to it
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
