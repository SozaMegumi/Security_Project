<?php include 'conn/conn.php'?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="Image/icon.ico" />
    <link rel="stylesheet" type="text/css" href="css/style.css" />
    <title>KLMarathon - Admin Page</title>
</head>

<body>
    <div class="container-6">
        
        <img class="data-logo" src="Image/Logo.png" alt="logo">
        <table>
            <tr class="search">
                <th colspan="3"> Participant Registration Table </th>
                <th colspan="5">
                    <form action="search.php" method="POST">
                        <div>
                            <p>
                                Search :
                                <input type="text" name="search" id="search">
                            </p>
                        </div>
                    </form>
                </th>
            </tr>
            <tr>
                <th class="top-header-left">No</th>
                <th>Name</th>
                <th>IC Number</th>
                <th>Phone Number</th>
                <th>Email</th>
                <th>Emergency Number</th>
                <th>Update</th>
                <th class="top-header-right">Delete</th>
            </tr>

            <?php
            $bil = 1;
            //perform query
            $query = "SELECT * FROM registration";
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
                <td><?php echo $bil;?></td>
                <td><?php echo $name;?></td>
                <td><?php echo $ic;?></td>
                <td><?php echo $phone;?></td>
                <td><?php echo $email;?></td>
                <td><?php echo $emerg;?></td>
                <td><a href="update.php?user_id=<?php echo $id;?>">Update</a></td>
                <td><a href="delete-engine.php?user_id=<?php echo $id;?>">Delete</a></td>
            </tr>
            <?php
            //end looping
            $bil++;
            }

            //shows number of data displayed
            if($notempty != 0){
            ?>
            <tr>
                <td class="bot-table" colspan="8">Showing result of <?php echo $bil-1 ?> data from database</td>
            </tr>
            <?php
            }
            //if data in db not existed
            if($notempty == 0){
            ?>

            <tr>
                <td class="bot-table" colspan="8"> No data inside the database </td>
            </tr>
            <?php } ?>

            <table>
                <tr>
                    <td style="background-color: transparent; border: unset; font-weight: 400;" colspan="3">User Message</td>
                </tr>
                <tr>
                    <th class="top-header-left">No</th>
                    <th>Name</th>
                    <th>Email</th>
                    <th class="msg-txt">Subject</th>
                    <th class="top-header-right">Message</th>
                </tr>

                <?php
                $no = 1;
                //perform query
                $querymsg = "SELECT * FROM message";
                $resultmsg = mysqli_query($conn,$querymsg);
                $notemptymsg = mysqli_num_rows($resultmsg);
                while($row = mysqli_fetch_assoc($resultmsg)){
                    $num = $row["msg_id"];
                    $msgName = $row["name"];
                    $msgEmail = $row["email"];
                    $msgSubject = $row["subject"];
                    $msgMesagge = $row["message_txt"];
                ?>
                <tr>
                    <td><?php echo $num;?></td>
                    <td><?php echo $msgName;?></td>
                    <td><?php echo $msgEmail?></td>
                    <td><?php echo $msgSubject?></td>
                    <td><?php echo $msgMesagge?></td>
                </tr>
                <?php
                //end loop
                $no++;
                }

                //shows number of data displayed
                if($notemptymsg != 0){
                ?>
                <tr>
                    <td class="bot-table" colspan="8">Showing result of <?php echo $no-1 ?> data from database</td>
                </tr>
                <?php
                }
                //if data in db not existed
                if($notemptymsg == 0){
                ?>
    
                <tr>
                    <td class="bot-table" colspan="8"> No data inside the database </td>
                </tr>
                <?php } ?>
                
            </table>

    </div>
</body>

</html>