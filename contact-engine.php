<?php
include 'conn/conn.php';

//retreive data from form
$name = $_REQUEST["name"];
$email = $_REQUEST["email"];
$subject = $_REQUEST["subject"];
$message = $_REQUEST["message"];

//insert into db
$sql = " INSERT INTO message
(`name` , `email` , `subject` , `message_txt`)
VALUES ( '$name' , '$email' , '$subject' , '$message')";

//check if if the data is a member of db
if ($conn->query($sql) === TRUE) {
    ?> 
    <script>
        alert('Your message have been accepted')
        window.location = 'index.html'
    </script>
    <?php
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}
$conn -> close();
?>