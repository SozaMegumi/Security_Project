<?php
include 'conn/conn.php';

//get value from form
$id=$_REQUEST['user_id'];

?>
<script>
var del = confirm("Are you sure you want to delete this registration?");
    if (del == true) {
        <?php
            //perform query 
            $sql = "DELETE FROM registration WHERE user_id = '$id'";

            //check if data deletion success
            if ($conn->query($sql) === TRUE) {
        ?>
            alert('Registration have been successfully deleted')
            window.location = 'signin.html'
        <?php
        } else {
            echo "Error:" .$sql . "<br>" .$conn->error;
        }
            $conn->close();
        ?>
    } else {
        window.location = 'signin.html'
    }
</script>





