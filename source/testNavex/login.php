<?php
 include 'password.php';
 $user = $_POST['username'];
 $sql="SELECT * FROM UserAccounts WHERE username='$user' AND password='$pass'";
 $result = mysqli_query($connection, $sql);
?>