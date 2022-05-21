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

list($width, $height, $type, $attr) = @getimagesize($_POST[url_name]);
$arr_out = array ("width"=>$width, "height"=>$height, 'type'=>$type, 'attr'=>$attr);
$arr_out = json_encode($arr_out);
echo $arr_out; 


?>