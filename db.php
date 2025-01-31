<?php
// db.php - Database connection file

$DB_HOST = "sql7.freesqldatabase.com";
$DB_NAME = "sql7760342";
$DB_USER = "sql7760342";
$DB_PASS = "eghu2671Uc";
$DB_PORT = 3306;

try {
    $pdo = new PDO(
        "mysql:host=$DB_HOST;port=$DB_PORT;dbname=$DB_NAME;charset=utf8mb4",
        $DB_USER,
        $DB_PASS,
        [ PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION ]
    );
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}
