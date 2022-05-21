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

$res = $wpdb->query("DELETE FROM `".$wpdb->prefix."adv_v_base` WHERE `id`= '".$_POST[id]."' LIMIT 1;") ;

if(!$res)die('error');
   if($_POST[time_management]=='undefined'){
 $_POST[start_date] = null;
 $_POST[end_date] = null;
 }
 // echo '-PL->'.$_POST[limit_clicks].'-TM->'.$_POST[time_management];
    if($_POST[limit_clicks]=='undefined'){
 $_POST[click_amount] = null;
 }
$res = $wpdb->query("INSERT INTO `".$wpdb->prefix."adv_v_base` (`id`, `ads_name`, `ads_url`, `block_width`, `block_height`, `ads_link_url`, `new_window`, `trace_clicks`, `time_management`, `start_date`, `end_date`, `limit_clicks`, `click_amount`, `clicks_left`) VALUES ('".$_POST[id]."', '".$_POST[ads_name]."', '".$_POST[ads_url]."', '".$_POST[block_width]."', '".$_POST[block_height]."', '".$_POST[ads_link_url]."', '".$_POST[new_window]."', '".$_POST[trace_clicks]."', '".$_POST[time_management]."', '".$_POST[start_date]."', '".$_POST[end_date]."', '".$_POST[limit_clicks]."', '".$_POST[click_amount]."' , '".$_POST[click_amount]."');") ;

if(!$res)die('error');
?>