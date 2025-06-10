<?php
session_start();
require_once 'conn/conn.php'; // Make sure this file properly initializes $pdo

function sanitize($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// Google reCAPTCHA secret key (removed trailing whitespace)
$recaptcha_secret = "6LcbBlwrAAAAACR058H2xHxQahvLDkD6jQFhFQBg";

// Check reCAPTCHA
if (!isset($_POST['g-recaptcha-response'])) {
    $_SESSION['error'] = 'reCAPTCHA is required.';
    header('Location: signin.php');
    exit();
}

$recaptcha_response = sanitize($_POST['g-recaptcha-response']);

// Verify reCAPTCHA
$url = 'https://www.google.com/recaptcha/api/siteverify';
$data = [
    'secret' => $recaptcha_secret,
    'response' => $recaptcha_response
];

$options = [
    'http' => [
        'header' => "Content-type: application/x-www-form-urlencoded\r\n",
        'method' => 'POST',
        'content' => http_build_query($data)
    ]
];

$context = stream_context_create($options);
$response = file_get_contents($url, false, $context);
$response_keys = json_decode($response, true);

if (!$response_keys['success']) {
    $_SESSION['error'] = 'reCAPTCHA verification failed.';
    header('Location: signin.php');
    exit();
}

// Get user inputs
if (!isset($_POST['Ic_num']) || !isset($_POST['email'])) {
    $_SESSION['error'] = 'All fields are required.';
    header('Location: signin.php');
    exit();
}

$IC_num = sanitize($_POST["Ic_num"]);
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
        $_SESSION['error'] = 'Invalid credentials!';
        header('Location: signin.php');
    }

} catch (PDOException $e) {
    error_log("Database error: " . $e->getMessage());
    $_SESSION['error'] = 'A system error occurred. Please try again.';
    header('Location: signin.php');
    exit();
}
?>