<?php 
include 'conn/conn.php';
$user_id = $_REQUEST['user_id'];
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="Image/icon.ico" />
    <link rel="stylesheet" type="text/css" href="css/style.css" />
    <title>KLMarathon - Update</title>
</head>

<body>
    <div class="container-6">
        <img src="Image/Logo.png" alt="logo">
        <table>
            <tr>
                <th class="top-header-left">Name</th>
                <th>IC Number</th>
                <th>Phone Number</th>
                <th>Email</th>
                <th>Emergency Number</th>
                <th>Update</th>
                <th class="top-header-right">Delete</th>
            </tr>

            <?php
            //perform query
            $bil = 1;
            $query = "SELECT * FROM registration WHERE user_id = '$user_id'";
            $result = mysqli_query($conn,$query);
            $notempty = mysqli_num_rows($result);
            //start looping
            while($row = mysqli_fetch_assoc($result)){
                $id = $row["user_id"];
                $name = $row["name"];
                $ic = $row["num_ic"];
                $phone = $row["phone_num"];
                $email = $row["email"];
                $emerg = $row["emerg_num"];
            ?>
            <tr>
                <td><?php echo $name;?></td>
                <td><?php echo $ic;?></td>
                <td><?php echo $phone;?></td>
                <td><?php echo $email;?></td>
                <td><?php echo $emerg;?></td>
                <td><a href="update.php?user_id=<?php echo $id;?>">Update</a></td>
                <td><a href="delete-engine.php?user_id=<?php echo $id;?>">Delete</a></td>
            </tr>
            <?php } 

            //shows number of data displayed
            if($notempty != 0){
            ?>
            <tr>
                <td class="bot-table" colspan="8">Showing result of <?php echo $bil ?> data from database</td>
            </tr>
            <?php
            } 
            ?>
        </table>
    </div>
</body>

</html>