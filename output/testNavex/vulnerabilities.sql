INSERT INTO vulnerabilities_phpSAFE(PHPI_PLUGIN, PHPI_FILE_BASE,PHPI_FILE_AND_DIR,PHPI_INDEX,PHPI_NAME,PHPI_OBJECT,PHPI_CLASS,PHPI_SCOPE,PHPI_VARIABLE_FUNCTION,PHPI_EXIST_DESTROYED,PHPI_CODE_TYPE,PHPI_INPUT,PHPI_OUTPUT,PHPI_FUNCTION,PHPI_FILE,PHPI_LINE,PHPI_TAINTED,PHPI_VULNERABILITY,PHPI_START_INDEX,PHPI_END_INDEX,PHPI_DEPENDENCIES_INDEX,PHPI_VARIABLE_FILTER,PHPI_VARIABLE_REVERT_FILTER, Data,Manually_verified, link, piece_of_code, execution_time,memory ) VALUES('testNavex','login.php','/phpSAFE2e/source/testNavex/login.php','9','$sql','','','local','variable','exist','php code','regular','output','function','/phpSAFE2e/source/testNavex/login.php','5','tainted','SQL Injection','27','27','4 ','','','2022-05-21 12:51:33','0','http://localhost:80/phpSAFE2e/show_php_file.php?file=C:\xampp74\htdocs\phpSAFE2e\source\testNavex\login.php&line_mark=5&line_end=4&variable_name=%24sql&text=123#target_mark','1 ## <?php2 ##  include 'password.php'#3 ##  $user = $_POST['username']#4 ##  $sql="SELECT * FROM UserAccounts WHERE username='$user' AND password='$pass'"#5 ##  $result = mysqli_query($connection, $sql)#','0.0010700225830078','64' );
INSERT INTO vulnerabilities_phpSAFE(PHPI_PLUGIN, PHPI_FILE_BASE,PHPI_FILE_AND_DIR,PHPI_INDEX,PHPI_NAME,PHPI_OBJECT,PHPI_CLASS,PHPI_SCOPE,PHPI_VARIABLE_FUNCTION,PHPI_EXIST_DESTROYED,PHPI_CODE_TYPE,PHPI_INPUT,PHPI_OUTPUT,PHPI_FUNCTION,PHPI_FILE,PHPI_LINE,PHPI_TAINTED,PHPI_VULNERABILITY,PHPI_START_INDEX,PHPI_END_INDEX,PHPI_DEPENDENCIES_INDEX,PHPI_VARIABLE_FILTER,PHPI_VARIABLE_REVERT_FILTER, Data,Manually_verified, link, piece_of_code, execution_time,memory ) VALUES('testNavex','login.php','/phpSAFE2e/source/testNavex/login.php','9','$sql','','','local','variable','exist','php code','regular','output','function','/phpSAFE2e/source/testNavex/login.php','5','tainted','SQL Injection','27','27','4 ','','','2022-05-21 12:51:33','0','http://localhost:80/phpSAFE2e/show_php_file.php?file=C:\xampp74\htdocs\phpSAFE2e\source\testNavex\login.php&line_mark=5&line_end=4&variable_name=%24sql&text=123#target_mark','1 ## <?php2 ##  include 'password.php'#3 ##  $user = $_POST['username']#4 ##  $sql="SELECT * FROM UserAccounts WHERE username='$user' AND password='$pass'"#5 ##  $result = mysqli_query($connection, $sql)#','0.0010700225830078','64' );