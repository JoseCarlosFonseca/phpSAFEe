INSERT INTO vulnerabilities_phpSAFE(PHPI_PLUGIN, PHPI_FILE_BASE,PHPI_FILE_AND_DIR,PHPI_INDEX,PHPI_NAME,PHPI_OBJECT,PHPI_CLASS,PHPI_SCOPE,PHPI_VARIABLE_FUNCTION,PHPI_EXIST_DESTROYED,PHPI_CODE_TYPE,PHPI_INPUT,PHPI_OUTPUT,PHPI_FUNCTION,PHPI_FILE,PHPI_LINE,PHPI_TAINTED,PHPI_VULNERABILITY,PHPI_START_INDEX,PHPI_END_INDEX,PHPI_DEPENDENCIES_INDEX,PHPI_VARIABLE_FILTER,PHPI_VARIABLE_REVERT_FILTER, Data,Manually_verified, link, piece_of_code, execution_time,memory ) VALUES('test','login.php','tdocs/phpSAFE2e/source/test/login.php','9','$sql','','','local','variable','exist','php code','regular','output','function','tdocs/phpSAFE2e/source/test/login.php','5','tainted','SQL Injection','31','31','4 ','','','2022-05-21 12:51:32','0','http://localhost:80/phpSAFE2e/show_php_file.php?file=C:\xampp74\htdocs\phpSAFE2e\source\test\login.php&line_mark=5&line_end=4&variable_name=%24sql&text=123#target_mark','1 ## <?php2 ##  $user = $_POST['username']#3 ##  $pass = $_POST['password']#4 ##  $sql="SELECT * FROM UserAccounts WHERE username='$user' AND password='$pass'"#5 ##  $result = mysqli_query($connection, $sql)#','0.0010378360748291','61' );
INSERT INTO vulnerabilities_phpSAFE(PHPI_PLUGIN, PHPI_FILE_BASE,PHPI_FILE_AND_DIR,PHPI_INDEX,PHPI_NAME,PHPI_OBJECT,PHPI_CLASS,PHPI_SCOPE,PHPI_VARIABLE_FUNCTION,PHPI_EXIST_DESTROYED,PHPI_CODE_TYPE,PHPI_INPUT,PHPI_OUTPUT,PHPI_FUNCTION,PHPI_FILE,PHPI_LINE,PHPI_TAINTED,PHPI_VULNERABILITY,PHPI_START_INDEX,PHPI_END_INDEX,PHPI_DEPENDENCIES_INDEX,PHPI_VARIABLE_FILTER,PHPI_VARIABLE_REVERT_FILTER, Data,Manually_verified, link, piece_of_code, execution_time,memory ) VALUES('test','login.php','tdocs/phpSAFE2e/source/test/login.php','9','$sql','','','local','variable','exist','php code','regular','output','function','tdocs/phpSAFE2e/source/test/login.php','5','tainted','SQL Injection','31','31','4 ','','','2022-05-21 12:51:32','0','http://localhost:80/phpSAFE2e/show_php_file.php?file=C:\xampp74\htdocs\phpSAFE2e\source\test\login.php&line_mark=5&line_end=4&variable_name=%24sql&text=123#target_mark','1 ## <?php2 ##  $user = $_POST['username']#3 ##  $pass = $_POST['password']#4 ##  $sql="SELECT * FROM UserAccounts WHERE username='$user' AND password='$pass'"#5 ##  $result = mysqli_query($connection, $sql)#','0.0010378360748291','61' );
INSERT INTO vulnerabilities_phpSAFE(PHPI_PLUGIN, PHPI_FILE_BASE,PHPI_FILE_AND_DIR,PHPI_INDEX,PHPI_NAME,PHPI_OBJECT,PHPI_CLASS,PHPI_SCOPE,PHPI_VARIABLE_FUNCTION,PHPI_EXIST_DESTROYED,PHPI_CODE_TYPE,PHPI_INPUT,PHPI_OUTPUT,PHPI_FUNCTION,PHPI_FILE,PHPI_LINE,PHPI_TAINTED,PHPI_VULNERABILITY,PHPI_START_INDEX,PHPI_END_INDEX,PHPI_DEPENDENCIES_INDEX,PHPI_VARIABLE_FILTER,PHPI_VARIABLE_REVERT_FILTER, Data,Manually_verified, link, piece_of_code, execution_time,memory ) VALUES('test','testSQLiXSS.php','tdocs/phpSAFE2e/source/test/testSQLiXSS.php','2','$user','','','local','variable','exist','php code','regular','output','function','tdocs/phpSAFE2e/source/test/testSQLiXSS.php','4','tainted','Cross Site Scripting','12','12','0 ','','','2022-05-21 12:51:32','0','http://localhost:80/phpSAFE2e/show_php_file.php?file=C:\xampp74\htdocs\phpSAFE2e\source\test\testSQLiXSS.php&line_mark=4&line_end=3&variable_name=%24user&text=123#target_mark','1 ## <?php2 ##  $user = $_POST['username']#3 ##  echo "Seach for User:"#4 ##  echo $user#','0.00093197822570801','59' );
INSERT INTO vulnerabilities_phpSAFE(PHPI_PLUGIN, PHPI_FILE_BASE,PHPI_FILE_AND_DIR,PHPI_INDEX,PHPI_NAME,PHPI_OBJECT,PHPI_CLASS,PHPI_SCOPE,PHPI_VARIABLE_FUNCTION,PHPI_EXIST_DESTROYED,PHPI_CODE_TYPE,PHPI_INPUT,PHPI_OUTPUT,PHPI_FUNCTION,PHPI_FILE,PHPI_LINE,PHPI_TAINTED,PHPI_VULNERABILITY,PHPI_START_INDEX,PHPI_END_INDEX,PHPI_DEPENDENCIES_INDEX,PHPI_VARIABLE_FILTER,PHPI_VARIABLE_REVERT_FILTER, Data,Manually_verified, link, piece_of_code, execution_time,memory ) VALUES('test','testSQLiXSS.php','tdocs/phpSAFE2e/source/test/testSQLiXSS.php','7','$sql','','','local','variable','exist','php code','regular','output','function','tdocs/phpSAFE2e/source/test/testSQLiXSS.php','6','tainted','SQL Injection','28','28','3 ','','','2022-05-21 12:51:32','0','http://localhost:80/phpSAFE2e/show_php_file.php?file=C:\xampp74\htdocs\phpSAFE2e\source\test\testSQLiXSS.php&line_mark=6&line_end=5&variable_name=%24sql&text=123#target_mark','1 ## <?php2 ##  $user = $_POST['username']#3 ##  echo "Seach for User:"#4 ##  echo $user#5 ##  $sql="SELECT * FROM UserAccounts WHERE username='$user'"#6 ##  $result = mysqli_query($connection, $sql)#','0.00093197822570801','59' );
INSERT INTO vulnerabilities_phpSAFE(PHPI_PLUGIN, PHPI_FILE_BASE,PHPI_FILE_AND_DIR,PHPI_INDEX,PHPI_NAME,PHPI_OBJECT,PHPI_CLASS,PHPI_SCOPE,PHPI_VARIABLE_FUNCTION,PHPI_EXIST_DESTROYED,PHPI_CODE_TYPE,PHPI_INPUT,PHPI_OUTPUT,PHPI_FUNCTION,PHPI_FILE,PHPI_LINE,PHPI_TAINTED,PHPI_VULNERABILITY,PHPI_START_INDEX,PHPI_END_INDEX,PHPI_DEPENDENCIES_INDEX,PHPI_VARIABLE_FILTER,PHPI_VARIABLE_REVERT_FILTER, Data,Manually_verified, link, piece_of_code, execution_time,memory ) VALUES('test','testSQLiXSS.php','tdocs/phpSAFE2e/source/test/testSQLiXSS.php','2','$user','','','local','variable','exist','php code','regular','output','function','tdocs/phpSAFE2e/source/test/testSQLiXSS.php','4','tainted','Cross Site Scripting','12','12','0 ','','','2022-05-21 12:51:32','0','http://localhost:80/phpSAFE2e/show_php_file.php?file=C:\xampp74\htdocs\phpSAFE2e\source\test\testSQLiXSS.php&line_mark=4&line_end=3&variable_name=%24user&text=123#target_mark','1 ## <?php2 ##  $user = $_POST['username']#3 ##  echo "Seach for User:"#4 ##  echo $user#','0.00093197822570801','59' );
INSERT INTO vulnerabilities_phpSAFE(PHPI_PLUGIN, PHPI_FILE_BASE,PHPI_FILE_AND_DIR,PHPI_INDEX,PHPI_NAME,PHPI_OBJECT,PHPI_CLASS,PHPI_SCOPE,PHPI_VARIABLE_FUNCTION,PHPI_EXIST_DESTROYED,PHPI_CODE_TYPE,PHPI_INPUT,PHPI_OUTPUT,PHPI_FUNCTION,PHPI_FILE,PHPI_LINE,PHPI_TAINTED,PHPI_VULNERABILITY,PHPI_START_INDEX,PHPI_END_INDEX,PHPI_DEPENDENCIES_INDEX,PHPI_VARIABLE_FILTER,PHPI_VARIABLE_REVERT_FILTER, Data,Manually_verified, link, piece_of_code, execution_time,memory ) VALUES('test','testSQLiXSS.php','tdocs/phpSAFE2e/source/test/testSQLiXSS.php','7','$sql','','','local','variable','exist','php code','regular','output','function','tdocs/phpSAFE2e/source/test/testSQLiXSS.php','6','tainted','SQL Injection','28','28','3 ','','','2022-05-21 12:51:32','0','http://localhost:80/phpSAFE2e/show_php_file.php?file=C:\xampp74\htdocs\phpSAFE2e\source\test\testSQLiXSS.php&line_mark=6&line_end=5&variable_name=%24sql&text=123#target_mark','1 ## <?php2 ##  $user = $_POST['username']#3 ##  echo "Seach for User:"#4 ##  echo $user#5 ##  $sql="SELECT * FROM UserAccounts WHERE username='$user'"#6 ##  $result = mysqli_query($connection, $sql)#','0.00093197822570801','59' );