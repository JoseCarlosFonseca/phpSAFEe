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
   
$res = $wpdb->query("DELETE FROM `".$wpdb->prefix."adv_v_base` WHERE `id` ='".$_POST[id]."' LIMIT 1;");
if(!$res) die('error deleting ads');
else
echo 'deleted!';

?>