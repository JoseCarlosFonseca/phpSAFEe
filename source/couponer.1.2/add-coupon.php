<?php
require_once("../../../wp-config.php");
global $wpdb;

echo '<div id="couponer_working" style="width:100%;height:100%;padding-top:100px;text-align:center;"><img src="images/working.gif" /><br /><br />Please Wait... Saving Coupon.</div>';

$Title=$_POST['Title'];
$Description=$_POST['Description'];
$Terms=$_POST['Terms'];
$Expires=$_POST['Exp-Y'].'-'.$_POST['Exp-M'].'-'.$_POST['Exp-D'];
$Image=$_POST['Image'];

$insert = "INSERT INTO wp_couponer".
            " (Title, Description, Terms, Expires, Image) " .
            "VALUES ('$Title','$Description','$Terms','$Expires','$Image')";
$results = $wpdb->query( $insert );

if ($results)    
{    
    echo '<META HTTP-EQUIV="Refresh" Content="0; URL=/wp-admin/options-general.php?page=couponer">';
    exit;
}    
else    
{    
    echo 'ERROR';
    exit;
} 
?>