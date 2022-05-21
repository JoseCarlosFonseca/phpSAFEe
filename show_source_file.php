<?php

$file = $_GET['file'];

//show_source($file);

?>

<style type="text/css">
.linenum{
    text-align:right;
    background:#FDECE1;
    border:1px solid #cc6666;
    padding:0px 1px 0px 1px;
    font-family:Courier New, Courier;
    float:left;
    width:17px;
    margin:3px 0px 30px 0px;
    }

code    {/* safari/konq hack */
    font-family:Courier New, Courier;
}

.linetext{
    //width:700px;
    text-align:left;
    background:white;
    border:1px solid #cc6666;
    border-left:0px;
    padding:0px 1px 0px 8px;
    font-family:Courier New, Courier;
    float:left;
    margin:3px 0px 30px 0px;
    }

br.clear    {
    clear:both;
}

</style>
<?php
function printCode($code, $lines_number = 0)    {
              
         if (!is_array($code)) $codeE = explode("\n", $code);
        $count_lines = count($codeE);
       
        $r1 = ""; // "Code:<br />";

         if ($lines_number){           
                $r1 .= "<div class=\"linenum\">";
                foreach($codeE as $line =>$c) {    
                    if($count_lines=='1')
                        $r1 .= "1<br>";
                    else
                        $r1 .= ($line == ($count_lines - 1)) ? "" :  ($line+1)."<br />";
                 }
                 $r1 .= "</div>";
         }

         $r2 = "<div class=\"linetext\">";
         $r2 .= highlight_string($code,1);
         $r2 .= "</div>";

        $r = $r1.$r2;

        echo "<div class=\"code\">".$r."</div>\n";
    }

	$code= file_get_contents($file);
	echo "<h2>File: $file</h2>";
    printCode($code,1);
?>

