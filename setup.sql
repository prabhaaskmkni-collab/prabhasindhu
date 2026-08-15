-- ═══════════════════════════════════════════════════════════
-- setup.sql — Run this in Hostinger hPanel > phpMyAdmin
-- ═══════════════════════════════════════════════════════════

-- 1. Create the users table
CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(50)  UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role          ENUM('user','admin') NOT NULL DEFAULT 'user',
  created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Insert the default admin account
--    Username : admin
--    Password : Admin@1234   ← CHANGE THIS IMMEDIATELY after first login!
INSERT INTO users (username, password_hash, role) VALUES (
  'admin',
  '$2y$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'admin'
);

-- ═══════════════════════════════════════════════════════════
-- HOW TO USE
-- ═══════════════════════════════════════════════════════════
-- 1. Log in to hPanel (hostinger.com)
-- 2. Go to Hosting → your plan → phpMyAdmin
-- 3. Select your database on the left panel
-- 4. Click the "SQL" tab at the top
-- 5. Paste the entire contents of this file and click "Go"
-- ═══════════════════════════════════════════════════════════
