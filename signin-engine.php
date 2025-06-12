<?php
session_start();
require_once 'conn/conn.php';

function sanitize($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

$recaptcha_secret = '6Lc19lsrAAAAAJPOp0lE_lpOmZoZyX1Rk3mNirAZ';

if (!isset($_POST['g-recaptcha-response'])) {
    header('Location: signin.html?error=4');
    exit();
}

$captcha_response = sanitize($_POST['g-recaptcha-response']);
$verify = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=$recaptcha_secret&response=$captcha_response&remoteip=" . $_SERVER['REMOTE_ADDR']);
$response_data = json_decode($verify, true);


if (!isset($_POST['Ic_Num'], $_POST['email'], $_POST['password'])) {
    header('Location: signin.html?error=3');
    exit();
}

$IC_num  = sanitize($_POST['Ic_Num']);
$email   = sanitize($_POST['email']);
$password = $_POST['password'];

// Admin shortcut
if ($IC_num === "adminlogin" && $email === "admin@KLMarathon.com") {
    $_SESSION['admin'] = true;
    header("Location: admin.php");
    exit();
}

// Normal user login
$stmt = $conn->prepare("SELECT userId, password FROM registration WHERE Ic_Num = ? AND email = ?");
$stmt->bind_param("ss", $Ic_Num, $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result && $result->num_rows > 0) {
    $user = $result->fetch_assoc();

    if (password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['userId'];
        header("Location: index.html");
        exit();
    }
}

header("Location: signin.html?error=1");
exit();
?>
