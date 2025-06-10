<?php 

include 'conn/conn.php';
$id = $_REQUEST["user_id"];
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="Image/icon.ico" />
    <link rel="stylesheet" type="text/css" href="css/style.css" />
    <title>KLMarathon - Update Details</title>
</head>

<?php
//perform selection query 
$query = "SELECT * FROM registration WHERE user_id ='$id'";
$result = mysqli_query($conn,$query);
while($row = mysqli_fetch_assoc($result)){
    $name = $row["name"];
    $ic = $row["num_ic"];
    $phone = $row["phone_num"];
    $email = $row["email"];
    $emerg = $row["emerg_num"];
?>

<body>
    <div class="container-4">
        <div class="cont-child">
            <div class="rightCont">
                <h1>Update Registation Details</h1>
                <hr>
                <form action="update-engine.php?user_id=<?php echo $id;?>" method="POST">
                    <label class="label" for="name">Name</label>
                    <input type="text" value="<?php echo $name ?>" name="name" required>

                    <label class="label" for="IC_num">IC Number</label>
                    <input type="text" value="<?php echo $ic ?>" name="IC_num" required>

                    <label class="label" for="phone">Phone Number</label>
                    <input type="tel" value="<?php echo $phone ?>" name="phone" required>

                    <label class="label" for="email">Email</label>
                    <input type="email" value="<?php echo $email ?>" name="email" required>

                    <label class="label" for="EmergNum">Emergency Contact Number</label>
                    <input type="text" value="<?php echo $emerg ?>" name="EmergNum" required>

                    <input type="submit" class="submit" value="Update">
                </form>
            </div>
        </div>
        <div class="cont-child">
            <div class="leftCont">
                <a href="index.html"><img src="Image/logo-white.png"></a>
                <h1>Update Registation Details</h1>
                <p>Tips: Make sure all the text field are filled correctly</p>
            </div>
        </div>
    </div>
</body>

<?php } ?>

</html>