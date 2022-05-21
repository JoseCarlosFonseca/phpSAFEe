<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
  2016-12-26
 */

// H:\_WORKLOAD_phpSAFE_runner\_phpSAFE_run\class-php-parser.php(1526):  
// $dependence_variables = urlencode(base64_encode(serialize($dependence_variables)));
// QTS $value = "<a href='../../_phpSAFE_run/show_php_file.php?file=$file_name&line_mark=$line_mark&line_end=$line_end&variable_name=" . $variable_name . "&text=$text#target_mark'>$value</a>";
//                 $value = "<a href='../../../_phpSAFE_run/show_php_file.php?file=$file_name&line_mark=$line_mark&line_end=$line_end&variable_name=" . $variable_name . "&text=$text&dependence_variables=$dependence_variables#target_mark'>$value</a>";

$menu = "";

function get_lines_of_code($file_name, $variable_name, $line, $lines, $line_mark, $line_end, $text, $dependence_variables) {
//$end_index = end_of_php_line($file_name, $end_index);
    global $menu;
    if ($line_mark === 0)
        $line_mark++;
    $line_end++;
    $file_name = realpath(dirname($file_name)) . DIRECTORY_SEPARATOR . basename($file_name);
    $text_lines = <<<_END
    <style type="text/css">
       table, th, td {border-collapse: collapse;}
			 a.mark {text-decoration: none; color:red; }
			 a.mark:hover {color:magenta; weight: bold;  }
			 
			  
    </style>
_END;

    $text_lines .= "<h2>File: $file_name</h2>";
   // $text_lines .= "<h2>What?: $text</h2>";
    $text_lines .= "<h2>Lines: $line_mark to $line_end</h2>";
    $text_lines .= "<table>";

    if ((file_exists($file_name) ) && (is_file($file_name))) {
        $file_contents = file_get_contents($file_name);
        $convert = preg_split('/\r\n|\r|\n/', $file_contents);
        //$convert = explode("\n", $file_contents); //create array separate by new line
        $a = ($line - $lines >= 0 ) ? $line - $lines : 0;
        $b = ($line + $lines < count($convert)) ? $line + $lines : count($convert) - 1;
        $mark = 0;
        for ($i = $a; $i < $b; $i++) {
            $text_line = htmlentities($convert[$i]); //write value by index
            $text_line = htmlspecialchars($convert[$i]); //write value by index

            $style = "";
            if (($i >= $line_mark - 1) && ($i < $line_end))
                $style = " style='border:1px solid black'";

            $target_mark = "";
            if ($i == $line_mark - 1)
                $target_mark = "id='target_mark'";

            if (is_array($dependence_variables))
                foreach ($dependence_variables as $key) {
                    $key = trim($key);
                    //echo $key . '- ';
                    if ($key != "")
                        $text_line = str_replace($key, "<span style='color:blue;font-weight: bold;font-size: large'>$key</span>", $text_line);
                       //$text_line = str_replace($key, "<span>$key</span>", $text_line);
                }
            //if ($i === $line_mark-1)
            //$variable_name0 = $variable_name;
            //$variable_name = str_replace(array('$', "'", '"'), array('%24', '%27', '%22'), $variable_name);
            // $variable_name_array = explode(" ",$variable_name);
            // foreach ($variable_name_array as $v) {
            // echo "$text_line, $v<br>";
            // if (strpos($text_line, $v)>0) {
            // $text_line = str_replace($v, "<span id='target_mark$mark' style='color:red;font-weight: bold;font-size: large'><a class='mark' href=''>$variable_name</a></span>", $text_line);
            // $menu .=  "<a href='#target_mark$mark'>" . ($i+1) ."</a> ";
            // $mark++;
            // }
            // }
                
            $variable_name = trim($variable_name);
            if ($variable_name != '') {
                //echo $variable_name;
              if (strpos($text_line, $variable_name) !== false) {
                   // $text_line = str_replace($variable_name, "<span style='color:red;font-weight: bold;font-size: large' id='target_mark$mark' ><a class='mark' href=''>$variable_name</a></span>", $text_line);
                    $text_line = str_replace($variable_name, "<span style='font-weight: bold;font-size: large' id='target_mark$mark' ><a class='mark' href=''>$variable_name</a></span>", $text_line);
                    $menu .= "<a href='#target_mark$mark'>" . ($i + 1) . "</a> ";
                    $mark++;
                }
            }

            //echo "<p>$variable_name <br>$text_line</p>";
            $text_lines .= "<tr><td $target_mark $style><pre>" . ($i + 1) . "</pre></td><td $style><pre>$text_line</pre></td></tr>";
        }
    } else {
        $text_lines .= "<tr><td>Cannot read the file.</td></tr>";
    }
    $text_lines .= "</table>";
    echo $menu;
    return $text_lines;
}

$file_name = htmlspecialchars($_GET['file']);
if (isset($_GET['line_mark']))
    $line_mark = intval($_GET['line_mark']);
else
    $line_mark = 0;
if (isset($_GET['line_end']))
    $line_end = intval($_GET['line_end']);
else
    $line_end = 0;
if (isset($_GET['variable_name']))
    $variable_name = htmlspecialchars($_GET['variable_name']);
else
    $variable_name = "";
if (isset($_GET['text']))
    $text = htmlspecialchars($_GET['text']);
else
    $text = "";

if (isset($_GET['dependence_variables']))
    $dependence_variables = unserialize(base64_decode(urldecode($_GET['dependence_variables'])));

if (!is_array($dependence_variables))
    $dependence_variables = array();


//'printf','vprintf',

$dependence_variables = array_merge($dependence_variables, array(
    'echo','fprintf', 'sprintf',
    'printf' ,  'print' ,  'print_r' , 'die',
   
    '$wpdb->query',
    '$wpdb->prepare',
    //'prepare',
    '$wpdb',
    '$_GET',
    '$_POST',
    '$_COOKIE',
    '$_REQUEST',
    '$_FILES',
    '$_SERVER',
    '$_ENV',
    '$HTTP_GET_VARS',
    '$HTTP_POST_VARS',
    '$HTTP_COOKIE_VARS',
    '$HTTP_REQUEST_VARS',
    '$HTTP_POST_FILES',
    '$HTTP_SERVER_VARS',
    '$HTTP_ENV_VARS',
    '$HTTP_RAW_POST_DATA',
    '$argc',
    '$argv'));


//echo __FILE__ . "<br>";
//print_r($dependence_variables);

echo "<h2>Vulnerable variable: <span style='color:red'>$variable_name</span></h2>";
echo "<p><a href='#target_mark'>Go to vulnerable line</a></p>";

echo get_lines_of_code($file_name, $variable_name, 0, 999999, $line_mark, $line_end, $text, $dependence_variables);

