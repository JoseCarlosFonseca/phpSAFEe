<?php
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

$res = $wpdb->get_results("SELECT `id`, `ads_name`, `ads_url`, `block_width`, `block_height`, `ads_link_url`, `new_window`, `trace_clicks`, `time_management`, `start_date`, `end_date`, `limit_clicks`, `click_amount`, `clicks_left`, `clicks_done`  FROM `".$wpdb->prefix."adv_v_base`;");

foreach ($res as $res1){

echo ' 
    <div id="ads_cont_list list_'.$res1->id.'" style="border: 1px dotted #000; margin:10px; padding:5px;">
    <div id="ads_img_block" style="float:left; width:15%; border:0px #f0f solid;">
    
    <div id="ads_image" style="width:100px; height:100px;"><img src="'.$res1->ads_url.'" style="width:100px; height:100px;" /></div>
    
    </div>
    
    <div  style="float:left;width:70%; border:0px #00f solid;" id="param_list">
    <div  style="float:left;">Ads name: <span id="ads_name_'.$res1->id.'">'.$res1->ads_name.'</span></div><br/>
    <div style="float:left;" >Ads image url: <span id="ads_url_'.$res1->id.'">'.$res1->ads_url.'</span></div><br/>
    <div style="float:left;" >Ads size: <span id="block_width_'.$res1->id.'">'.$res1->block_width.'</span> x <span id="block_height_'.$res1->id.'">'.$res1->block_height.'</span></div><br/>
    <div style="float:left;" >Ads URL: <span id="ads_link_url_'.$res1->id.'">'.$res1->ads_link_url.'</span></div><br/>
    <div style="float:left;" >New Window: ';
    
    if($res1->new_window == 1)
    echo '<span class="turn_on" id="new_window_'.$res1->id.'">Turned On</span>';
    else
    echo '<span class="turn_off" id="new_window_'.$res1->id.'">Turned Off</span>';
    echo '</div><br/>
    <div style="float:left;" >Trace clicks: ';
    if($res1->trace_clicks == 1)
    echo '<span class="turn_on" id="trace_clicks_'.$res1->id.'">Turned On</span>';
    else
    echo '<span class="turn_off" id="trace_clicks_'.$res1->id.'">Turned Off</span>';
    echo '</div><br/>
    <div style="float:left;" >Time management: <span';
    if($res1->time_management == 1)
    echo ' class="turn_on" ';
    else
    echo ' class="turn_off"  ';
    echo ' id="time_management_'.$res1->id.'">';
    
    if($res1->time_management == 1)
    echo 'Turned On';
    else
    echo 'Turned Off';
    
    echo '</span> <span id="start_date_'.$res1->id.'">'.$res1->start_date.'</span> - <span id="end_date_'.$res1->id.'">'.$res1->end_date.'</span></div><br/>
    <div style="float:left;">Click Limit: ';
    
    if($res1->limit_clicks == 1)
    echo '<span class="turn_on" id="limit_clicks_'.$res1->id.'">Turned On</span>';
    else
    echo '<span class="turn_off" id="limit_clicks_'.$res1->id.'">Turned off</span>';
    echo ' <span id="click_amount_'.$res1->id.'">'.$res1->click_amount.'</span></div><br/>
    <div style="float:left;" >Clicks Left : '.$res1->clicks_left.'</div><br/>
    <div style="float:left;" >Clicks Done : ';
    if(!$res1->clicks_done) 
      echo '<span id="clicks_done_'.$res1->id.'">No clicks</span>';
        else
      echo '<span id="clicks_done_'.$res1->id.'">'.$res1->clicks_done.'</span>';
    echo '</div><br/>
    </div>
    
     <div id="control" style="float:left; width:10%;">
     <input type="button" class="button-primary" onClick="edit_ads('.$res1->id.');" id="edit_control" size="15" value="Edit">
     <input type="button" class="button-primary" onClick="del_ads('.$res1->id.');" id="del_control" size="15" value="Delete">
     </div>
     <div style="clear:both; border-bottom:0px dotted #000;"></div>
     </div>
    <div style="clear:both; border-bottom:0px dotted #000;"></div>';
    }
?>