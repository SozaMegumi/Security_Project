<?php
session_start();
require_once 'db.php'; // Make sure this connects using PDO

function sanitize($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// Google reCAPTCHA secret key
$recaptcha_secret = "6LcbBlwrAAAAACR058H2xHxQahvLDkD6jQFhFQBg   ";

// Check reCAPTCHA
if (!isset($_POST['g-recaptcha-response'])) {
    echo "<script>alert('reCAPTCHA is required.'); window.location.href='signin.php';</script>";
    exit();
}

$recaptcha_response = $_POST['g-recaptcha-response'];
$response = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=$recaptcha_secret&response=$recaptcha_response");
$response_keys = json_decode($response, true);

if (!$response_keys['success']) {
    echo "<script>alert('reCAPTCHA failed. Try again.'); window.location.href='signin.php';</script>";
    exit();
}

// Get user inputs
$IC_num = sanitize($_POST["IC_num"]);
$email = sanitize($_POST["email"]);

try {
    // Admin login check
    if ($IC_num === "adminlogin" && $email === "admin@KLMarathon.com") {
        $_SESSION['admin'] = true;
        header("Location: admin.php");
        exit();
    }

    // Normal user login
    $stmt = $pdo->prepare("SELECT user_id FROM registration WHERE num_ic = :ic AND email = :email");
    $stmt->execute([
        ':ic' => $IC_num,
        ':email' => $email
    ]);

    if ($stmt->rowCount() > 0) {
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        $_SESSION['user_id'] = $user['user_id'];
        header("Location: details.php?user_id=" . urlencode($user['user_id']));
        exit();
    } else {
        echo "<script>alert('Invalid credentials!'); window.location.href='signin.php';</script>";
    }

} catch (PDOException $e) {
    echo "Database error: " . $e->getMessage();
}
?>
