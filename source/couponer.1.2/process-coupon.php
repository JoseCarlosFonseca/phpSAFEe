<?php
require_once("../../../wp-config.php");
global $wpdb;

echo '<div id="couponer_working" style="width:100%;height:100%;padding-top:100px;text-align:center;"><img src="images/working.gif" /><br /><br />Please Wait... Processing Your Request.</div>';


if($_GET['mode'] == 'delete') {

   if($_GET['ID']) {

      $delete_coupon = "DELETE FROM wp_couponer WHERE ID='" . mysql_real_escape_string($_GET['ID']) . "'";
		
      mysql_query($delete_coupon);
   }
}
	if ($delete_coupon)    
	{    
	    echo '<META HTTP-EQUIV="Refresh" Content="0; URL='.get_bloginfo("url").'/wp-admin/options-general.php?page=couponer">';
	    exit;
	}


if($_GET['mode'] == 'deactivate') {

   if($_GET['ID']) {

      $deactivate_coupon = "UPDATE wp_couponer SET Active='0' WHERE ID='" . mysql_real_escape_string($_GET['ID']) . "'";

      mysql_query($deactivate_coupon);
   }
}
	if ($deactivate_coupon)    
	{    
		
	    echo '<META HTTP-EQUIV="Refresh" Content="0; URL='.get_bloginfo("url").'/wp-admin/options-general.php?page=couponer">';
	    exit;
	} 


if($_GET['mode'] == 'activate') {

   if($_GET['ID']) {

      $activate_coupon = "UPDATE wp_couponer SET Active='1' WHERE ID='" . mysql_real_escape_string($_GET['ID']) . "'";

      mysql_query($activate_coupon);
   }
}
	if ($activate_coupon)    
	{    
	    echo '<META HTTP-EQUIV="Refresh" Content="0; URL='.get_bloginfo("url").'/wp-admin/options-general.php?page=couponer">';
	    exit;
	} 


if($_GET['mode'] == 'couponerlogo') {

   if($_POST['Couponer_Logo']) {

      $newvalue = $_POST['Couponer_Logo'];
	  
	  update_option('Couponer_Logo', $newvalue);
   }
}
	if ($newvalue)    
	{    
	    echo '<META HTTP-EQUIV="Refresh" Content="0; URL='.get_bloginfo("url").'/wp-admin/options-general.php?page=couponer">';
	    exit;
	} 	
	
else    
{    
    echo 'ERROR: '.mysql_error();
    exit;
} 
?>