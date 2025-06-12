<?php
session_start();
require_once 'conn/conn.php';

function sanitize($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// Google reCAPTCHA secret key
$recaptcha_secret = '6Lc19lsrAAAAAJPOp0lE_lpOmZoZyX1Rk3mNirAZ';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name     = sanitize($_POST['name']);
    $IC_Num   = sanitize($_POST['Ic_Num']);
    $Phone_Num   = sanitize($_POST['Phone_Num']);
    $email    = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];
    $captcha  = $_POST['g-recaptcha-response'];

    // CAPTCHA verification
    if (empty($captcha)) {
        die("Please complete the CAPTCHA.");
    }

    $verify = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=$recaptcha_secret&response=$captcha&remoteip=" . $_SERVER['REMOTE_ADDR']);
    $response = json_decode($verify);
    

    // Password validation
    if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/', $password)) {
        die("Password must contain uppercase, lowercase, number, special char and min 8 characters.");
    }

    try {
        $stmt = $conn->prepare("SELECT * FROM registration WHERE Ic_Num = ? OR email = ?");
        $stmt->bind_param("ss", $Ic_Num, $email);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            die("IC number or email already registered.");
        }

        $hashed = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $conn->prepare("INSERT INTO registration (name, Ic_Num, password, Phone_Num, email) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $name, $IC_Num, $hashed, $Phone_Num, $email);
        $stmt->execute();

        // Redirect to sign in page after successful registration
        header("Location: signin.html");
        exit();
    } catch (Exception $e) {
        die("Database error: " . $e->getMessage());
    }
} else {
    die("Invalid request.");
}
?>
