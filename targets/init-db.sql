-- init-db.sql: seed data for MySQL benchmark target

CREATE DATABASE IF NOT EXISTS app_db;
USE app_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    balance INT DEFAULT 0,
    phone VARCHAR(20),
    id_card VARCHAR(20),
    salary INT,
    address VARCHAR(200),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, password, email, role, balance, phone, id_card, salary, address) VALUES
('admin', 'admin123', 'admin@target.bench', 'admin', 999999, '13800138000', '110101199001011234', 50000, 'Admin HQ'),
('zhangsan', 'zs123456', 'zhangsan@target.bench', 'user', 10000, NULL, NULL, NULL, NULL),
('lisi', 'ls123456', 'lisi@target.bench', 'user', 5000, NULL, NULL, NULL, NULL);
