<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <link rel="icon" href="Image/icon.ico" />
  <link rel="stylesheet" href="css/style.css" />
  <title>KLMarathon - Sign In</title>

  <!-- reCAPTCHA -->
  <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>
  <div class="container-4">
    <div class="cont-child">
      <div class="leftCont">
        <a href="index.html"><img src="Image/logo-white.png" alt="Logo" /></a>
        <h1>New Here?</h1>
        <p>Register for the marathon and<br> start your race with us now</p>
        <a class="button" href="register.html">Register</a>
      </div>
    </div>
    <div class="cont-child">
      <div class="rightCont">
        <h1>Update your details here</h1>
        <hr />
        <p>Sign in with the credentials you registered with</p>

        <?php
          session_start();
          if (isset($_SESSION['error'])) {
            echo "<p style='color:red; font-weight:bold'>" . $_SESSION['error'] . "</p>";
            unset($_SESSION['error']);
          }
        ?>

        <form action="signin-engine.php" method="POST">
          <label class="label" for="IC_num">IC Number</label>
          <input type="text" name="IC_num" placeholder="IC number" required />

          <label class="label" for="email">Email</label>
          <input type="email" name="email" placeholder="Email" required />

          <!-- Google reCAPTCHA -->
          <div class="g-recaptcha" data-sitekey="6LcbBlwrAAAAADszQ8QkAg8TMUArDnsiP71nFxm5"></div>

          <input type="submit" class="submit" value="Sign In" />
        </form>
      </div>
    </div>
  </div>
</body>
</html>
