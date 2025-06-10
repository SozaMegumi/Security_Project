<?php
session_start();
require_once 'conn/conn.php'; // Your database connection

function sanitize($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// Google reCAPTCHA secret key
$recaptcha_secret = '6Lc19lsrAAAAAJPOp0lE_lpOmZoZyX1Rk3mNirAZ';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitize inputs
    $name     = sanitize($_POST['name']);
    $IC_num   = sanitize($_POST['IC_num']);
    $phone    = sanitize($_POST['phone']);
    $email    = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];
    $captcha  = $_POST['g-recaptcha-response'];

    // CAPTCHA verification
    if (empty($captcha)) {
        die("Please complete the CAPTCHA.");
    }

    $verify = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret={$recaptcha_secret}&response={$captcha}&remoteip=" . $_SERVER['REMOTE_ADDR']);
    $response = json_decode($verify);



    // Password validation
    if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/', $password)) {
        die("Password must include uppercase, lowercase, number, special character and be at least 8 characters.");
    }

    try {
        $pdo = new PDO("mysql:host=localhost;dbname=marathon", "root", "");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Optional: check if IC or email exists
        $stmt = $pdo->prepare("SELECT * FROM registration WHERE Ic_Num = :IC_num OR email = :email");
        $stmt->execute(['IC_num' => $IC_num, 'email' => $email]);
        if ($stmt->rowCount() > 0) {
            die("IC Number or Email already registered.");
        }

        // Salt & hash password
        $salt = bin2hex(random_bytes(8));
        $hashed = password_hash($password . $salt, PASSWORD_DEFAULT);
        $combined = $hashed . ":" . $salt;

        // Insert into your database
        $stmt = $pdo->prepare("INSERT INTO registration (name, Ic_Num, password, Phone_Num, email) 
                               VALUES (:name, :IC_num, :password_hash, :phone, :email)");
        $stmt->execute([
            'name'          => $name,
            'IC_num'        => $IC_num,
            'password_hash' => $combined,
            'phone'         => $phone,
            'email'         => $email
        ]);

        header("Location: index.html");
        exit();
    } catch (PDOException $e) {
        die("Database error: " . $e->getMessage());
    }
} else {
    die("Invalid request.");
}
