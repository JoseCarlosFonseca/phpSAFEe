<?php
 $user = $_POST['username'];
 $pass = $_POST['password'];
 $sql="SELECT * FROM UserAccounts WHERE username='$user' AND password='$pass'";
 $result = mysqli_query($connection, $sql);
?>