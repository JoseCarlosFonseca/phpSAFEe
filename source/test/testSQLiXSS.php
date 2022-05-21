<?php
 $user = $_POST['username'];
 echo "Seach for User:";
 echo $user;
 $sql="SELECT * FROM UserAccounts WHERE username='$user'";
 $result = mysqli_query($connection, $sql);
?>
