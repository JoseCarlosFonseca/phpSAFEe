<?php
	// delete the database
    global $wpdb;
    $couponer = $wpdb->prefix . 'couponer';
    $wpdb->query("DROP TABLE IF EXISTS $couponer");
 
    // delete associated wp_options
    delete_option('Couponer_Logo');
    delete_option('couponer_db_version');
?>