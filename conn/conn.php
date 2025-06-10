<?php
$conn = new mysqli("localhost", "root", "", "marathon");

if($conn->connect_error){
    die ("connnection: " . $conn->connect_error);
}
?>