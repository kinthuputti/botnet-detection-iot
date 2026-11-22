-- Optional: import this in phpMyAdmin (XAMPP). The app also creates it automatically on first run.
CREATE DATABASE IF NOT EXISTS botnet_db CHARACTER SET utf8mb4;
USE botnet_db;

CREATE TABLE IF NOT EXISTS users (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    username   VARCHAR(80)  NOT NULL,
    email      VARCHAR(120) NOT NULL UNIQUE,
    phone      VARCHAR(20)  NOT NULL,
    address    VARCHAR(255) NOT NULL,
    password   VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
