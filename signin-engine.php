<?php
session_start();
require_once 'conn/conn.php'; // $conn is defined here (MySQLi)

function sanitize($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// reCAPTCHA secret key
$recaptcha_secret = "6LcbBlwrAAAAACR058H2xHxQahvLDkD6jQFhFQBg";

// Check reCAPTCHA presence
if (!isset($_POST['g-recaptcha-response'])) {
    $_SESSION['error'] = 'reCAPTCHA is required.';
    header('Location: signin.html');
    exit();
}

$recaptcha_response = sanitize($_POST['g-recaptcha-response']);

// Verify reCAPTCHA with Google
$verify_url = 'https://www.google.com/recaptcha/api/siteverify';
$data = [
    'secret' => $recaptcha_secret,
    'response' => $recaptcha_response,
    'remoteip' => $_SERVER['REMOTE_ADDR']
];

$options = [
    'http' => [
        'method'  => 'POST',
        'header'  => 'Content-type: application/x-www-form-urlencoded',
        'content' => http_build_query($data)
    ]
];

$context  = stream_context_create($options);
$verify_response = file_get_contents($verify_url, false, $context);
$response_data = json_decode($verify_response, true);

// Check CAPTCHA success
if (!$response_data['success']) {
    $_SESSION['error'] = 'CAPTCHA verification failed.';
    header('Location: signin.html');
    exit();
}

// Check form inputs
if (!isset($_POST['IC_num']) || !isset($_POST['email'])) {
    $_SESSION['error'] = 'All fields are required.';
    header('Location: signin.html');
    exit();
}

$IC_num = sanitize($_POST['IC_num']);
$email  = sanitize($_POST['email']);

// Admin login
if ($IC_num === "adminlogin" && $email === "admin@KLMarathon.com") {
    $_SESSION['admin'] = true;
    header("Location: admin.php");
    exit();
}

// User login (MySQLi)
$stmt = $conn->prepare("SELECT userId FROM registration WHERE Ic_Num = ? AND email = ?");
$stmt->bind_param("ss", $IC_num, $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $user = $result->fetch_assoc();
    $_SESSION['user_id'] = $user['userId'];
    header("Location: index.html");
    exit();
} else {
    $_SESSION['error'] = 'Invalid credentials.';
    header('Location: signin.html');
    exit();
}
?>
