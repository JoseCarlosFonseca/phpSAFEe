<?
$wp_load = realpath("../../../wp-load.php");
if(!file_exists($wp_load)) {
  $wp_config = realpath("../../../wp-config.php");
  if (!file_exists($wp_config)) {
      exit("Can't find wp-config.php or wp-load.php");
  } else {
      require_once($wp_config);
  }
} else {
  require_once($wp_load);
}
?>
<?

$res = $wpdb->get_row("SELECT `limit_clicks`, `trace_clicks` FROM `".$wpdb->prefix."adv_v_base` WHERE `id` = '".$_POST[id]."' limit 1;");

if($res->limit_clicks){   
$res_in = $wpdb->query("UPDATE `".$wpdb->prefix."adv_v_base` SET `clicks_left`=`clicks_left`-1 WHERE `id`=".$_POST[id].";");
  if(!$res_in) 
    die('error dereasing');
}
if($res->trace_clicks){   
$res_in = $wpdb->query("UPDATE `".$wpdb->prefix."adv_v_base` SET `clicks_done`=`clicks_done`+1 WHERE `id`= '".$_POST[id]."' LIMIT 1;");
  if(!$res_in) 
    die('error increasing');
}



?>