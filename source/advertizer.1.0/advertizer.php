<?php
/*
Plugin Name: Advertizer
Plugin URI: http://voodoopress.net/?page_id=15
Description: Advertizing management script
Author: Evgen  Dobrzhanskiy
Version: 1.0
Author URI: http://voodoopress.net

*/ 

/***!!!! DB ZONE !!!****/
/* DB generation BEGIN*/
register_activation_hook( __FILE__, 'adv_v_base' );
function adv_v_base(){
global $wpdb; 
$res = $wpdb->query("CREATE TABLE `".$wpdb->prefix."adv_v_base` (
  `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
  `ads_name` varchar(10) COLLATE utf8_unicode_ci DEFAULT NULL,
  `ads_url` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `block_width` varchar(10) COLLATE utf8_unicode_ci DEFAULT NULL,
  `block_height` varchar(10) COLLATE utf8_unicode_ci DEFAULT NULL,
  `ads_link_url` varchar(255) COLLATE utf8_unicode_ci DEFAULT NULL,
  `new_window` varchar(1) COLLATE utf8_unicode_ci DEFAULT NULL,
  `trace_clicks` varchar(1) COLLATE utf8_unicode_ci DEFAULT NULL,
  `time_management` varchar(1) COLLATE utf8_unicode_ci DEFAULT NULL,
  `start_date` varchar(10) COLLATE utf8_unicode_ci DEFAULT NULL,
  `end_date` varchar(10) COLLATE utf8_unicode_ci DEFAULT NULL,
  `limit_clicks` varchar(1) COLLATE utf8_unicode_ci DEFAULT NULL,
  `click_amount` varchar(10) COLLATE utf8_unicode_ci DEFAULT NULL,
  `clicks_left` varchar(10) COLLATE utf8_unicode_ci DEFAULT NULL,
  `clicks_done` varchar(10) COLLATE utf8_unicode_ci DEFAULT 0,
  
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=1 ;
");
if(!res) die('Cant create tabe');
}
/* DB generation END*/


/*  Script and style equation Begin */
wp_enqueue_script('adv_advertizer', WP_PLUGIN_URL . '/advertizer/js/advertizer.js.php', array('jquery'),'1.0' );
wp_enqueue_script('jquery-ui', WP_PLUGIN_URL . '/advertizer/js/jquery-ui-1.7.3.custom.min.js', array('jquery'),'1.0' );
wp_enqueue_script('jquery-datepicker', WP_PLUGIN_URL . '/advertizer/js/datepicker.js', array('jquery'),'1.0' );


wp_enqueue_style('datepick_opt_css', WP_PLUGIN_URL . '/advertizer/css/jquery-ui-1.7.3.custom.css');
wp_enqueue_style('personal_css', WP_PLUGIN_URL . '/advertizer/css/personal.css');

/*  Script equation END */

/* Admin Menu generator BEGIN */
/*
add_action('admin_menu', 'adv_v_gen');
function adv_v_gen() {
  add_menu_page('Advertizer Featured', 'Advertizer', 'manage_options',  'adv_v_script',  'add_v_advert');
  add_submenu_page('adv_v_script', 'Add Advertizing', 'Add Advert', 'manage_options', 'add_v_advertizing','add_ads_v_advert');
  add_submenu_page('adv_v_script', 'Viev Ads Stat', 'Ads stat', 'manage_options', 'ads_v_stat','get_ads_v_stat');
}
    */
add_action('admin_menu', 'adv_v_gen');    
function adv_v_gen() {
add_options_page('Advertizer Featured', 'Advertizer  <img src="'.WP_PLUGIN_URL .'/advertizer/images/advert.gif"  />', 'manage_options', 'add_v_advertizing', 'add_ads_v_advert');

}
/* Admin Menu generator END */


/***** CORE FUNCTIONS BEGIN **********/
function add_ads_v_advert(){
     echo '<input class="button-primary" type="button" value="Show Form" id="show_add_form">
     <div id="add_ads_form" style="display:none; width:600px; border:0px solid #000;">
     <form action='.$_SERVER[PHP_SELF].'" method="POST">
     <input type="hidden" id="upd_id">
     <h4 style="margin:0px; border-bottom:1px dotted #000;">Add Ads block form: </h4>
     <div style="width:50%; float:left; border: 0px solid #00a; text-align:right;">
     
     <label>Enter Ads block name: </label><input type="text" size="20" id="ads_name"><br/>
     <label>Enter URL of Ads image: </label><input type="text" size="20" id="ads_url"><input type="button" class="button-primary" value="Detect Image Size" id="detect_img_size"><br/>
     <label>Ads block width (px): </label><input disabled type="text" size="20" id="block_width"><br/>
     <label>Ads block height (px): </label><input disabled type="text" size="20" id="block_height"><br/>
     <label>Link URL: </label><input type="text" size="20" id="ads_link_url"><br/>
     </div>
     <div style="width:49%; float:left; border: 0px solid #00a; text-align:right;">
     <label>Open Ads in new window: </label><input type="checkbox" checked id="new_window" value="1"><br/>
     <label>Trace clicks: </label><input type="checkbox" checked id="trace_clicks"  value="1"><br/>
     <label>Time management of banner: </label><input type="checkbox" id="time_management" value="1"><br/>
     <div id="timing" style="display:none;">
     <label>Ads starts: </label><input type="text" size="20" id="start_date"><br/>
     <label>Ads ends: </label><input type="text" size="20" id="end_date"><br/>
     </div>
     <label>Limit clicks amount: </label><input type="checkbox" id="limit_clicks" value="1"><br/>
     <div id="clicking" style="display:none;">
     <label>Remove Ads after N clicks:</label><input type="text" size="10" id="click_amount"><br/>
     </div>
     </div>
     <div style="clear:both; border-bottom:1px dotted #000; "></div>
     <div style="text-align:center; margin: 10px auto;">
     <input type="button" class="button-primary" size="10" value="Submit" id="sumbit_ads">
     <input type="button" class="button-primary" size="10" value="Update"  style="display:none;" id="update_ads">
     <input type="reset" class="button-primary" size="10" value="Clear" id="clear_fields">
     </div>
     </form>
     </div>
     
     <!------------>
    <div id="existed_ads" style="width:95%; border:0px solid #000;">
   
    </div>
     
     ';
}

function get_ads_v_stat(){
echo 'get ads list adb';
}
/***** CORE FUNCTIONS END ************/




/* View all booked data BEGIN*/
function view_calendar(){
 echo 'View calendar';
}
/* View all booked data END*/








?>
<?
/* Widget Generation BEGIN */
class Advertizer extends WP_Widget {
function Advertizer() {
parent::WP_Widget(false, $name = 'Advertizer');
}

function widget($args, $instance) {
global $wpdb;
  extract( $args );
    $res = $wpdb->get_row("SELECT `ads_url`, `ads_link_url`, `new_window`, `limit_clicks` FROM `".$wpdb->prefix."adv_v_base` WHERE `id`='".$instance['ads_id']."' LIMIT 1; ");
    
  if(esc_attr($instance['ads_title_show']) == 1)
    echo $before_title.$instance['ads_title'].$after_title;
  echo '<div style="width:100%; text-align:center; ">';
  echo '<a href="'.$res->ads_link_url.'"';
  if ($res->new_window == 1) echo ' target="_blank" ';
  if ($res->limit_clicks) echo ' onClick="click_ads('.$instance['ads_id'].');" ';
  echo '><img src="'.$res->ads_url.'" /></a>';
  echo '</div>';


}

function update($new_instance, $old_instance) {
return $new_instance;
}

/********* PRINT  WIDGET BACKEND FORM ***********/
function form($instance) {
global $wpdb;
  $title = esc_attr($instance['ads_id']);
  $res = $wpdb->get_results("SELECT `id`, `ads_name` FROM `".$wpdb->prefix."adv_v_base`; ");
  echo '<p><label>Select ads block: </label><br/><select id="'.$this->get_field_id('title').'" name="'.$this->get_field_name('ads_id').'">';
  foreach ($res as $res_fin){
  echo '<option value="'.$res_fin->id.'"';
  if ($res_fin->id == esc_attr($instance['ads_id']) ) echo ' selected ';
  echo '>'.$res_fin->ads_name.'</option>';
  }
  echo '</select></p>';
  echo '
  <p><label>Title of widget: </label><input type="input" name="'.$this->get_field_name('ads_title').'" value="'.esc_attr($instance['ads_title']).'"> Show title: <input type="checkbox" name="'.$this->get_field_name('ads_title_show').'" value="1"';
if(esc_attr($instance['ads_title_show']) == 1)
echo ' checked ';  
echo '></p>';

}

}
add_action('widgets_init', create_function('', 'return register_widget("Advertizer");'));
/* Widget Generation END */
?>