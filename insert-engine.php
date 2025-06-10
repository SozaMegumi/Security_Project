<?php
session_start();
require_once 'db.php'; // Contains your DB connection

function sanitize($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// reCAPTCHA secret key
$recaptcha_secret = '6Lc19lsrAAAAAJPOp0lE_lpOmZoZyX1Rk3mNirAZ';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Sanitize inputs
    $user_id  = sanitize($_POST['user_id']);
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

    if (!$response->success) {
        die("CAPTCHA failed. Try again.");
    }

    // Password validation
    if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/', $password)) {
        die("Password must include uppercase, lowercase, number, special character and be at least 8 characters.");
    }

    try {
        // Connect securely
        $pdo = new PDO("mysql:host=localhost;dbname=marathon", "root", "");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Check if user_id or email already exists
        $stmt = $pdo->prepare("SELECT user_id FROM users WHERE user_id = :user_id OR email = :email");
        $stmt->execute(['user_id' => $user_id, 'email' => $email]);
        if ($stmt->rowCount() > 0) {
            die("User ID or Email already registered.");
        }

        // Salt & hash password
        $salt = bin2hex(random_bytes(8));
        $hashed = password_hash($password . $salt, PASSWORD_DEFAULT);
        $combined = $hashed . ":" . $salt;

        // Insert user (without emergency_num)
        $stmt = $pdo->prepare("INSERT INTO users (user_id, name, IC_num, phone, email, password_hash) 
                               VALUES (:user_id, :name, :IC_num, :phone, :email, :password_hash)");
        $stmt->execute([
            'user_id'       => $user_id,
            'name'          => $name,
            'IC_num'        => $IC_num,
            'phone'         => $phone,
            'email'         => $email,
            'password_hash' => $combined
        ]);

        // Redirect to index.html
        header("Location: index.html");
        exit();
    } catch (PDOException $e) {
        die("Error: " . $e->getMessage());
    }
} else {
    die("Invalid request.");
}
