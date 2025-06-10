<?php
include 'conn/conn.php';

//fetch value from form
$id = $_REQUEST["user_id"];
$name = $_REQUEST["name"];
$ic = $_REQUEST["IC_num"];
$phone = $_REQUEST["phone"];
$email = $_REQUEST["email"];
$emerg = $_REQUEST["EmergNum"];

//insert new values into db
$sql ="UPDATE registration
SET name='$name',
num_ic = '$ic',
phone_num = '$phone',
email = '$email',
emerg_num = '$emerg'
WHERE user_id = '$id'";

//if data inserted success
if ($conn->query($sql) === TRUE) { 
    ?>

<script>alert('Your data have been updated');
 window.location='signin.html';</script>

 <?php
 //if data failed to insert
} else {
    echo "Error:" .$sql . "<br>" .$conn->error;
}
$conn->close();
?>