<?
$wp_load = realpath("../../../../wp-load.php");
if(!file_exists($wp_load)) {
  $wp_config = realpath("../../../../wp-config.php");
  if (!file_exists($wp_config)) {
      exit("Can't find wp-config.php or wp-load.php");
  } else {
      require_once($wp_config);
  }
} else {
  require_once($wp_load);
}
?>
function change_to_hide(){
  jQuery("#add_ads_form").hide(500);
  jQuery("#show_add_form").val('Show Form');
}

function change_to_show(){
  jQuery("#add_ads_form").show(500);
  jQuery("#show_add_form").val('Hide Form');
}
/***************** BASE *****************/

jQuery(document).ready(function($){
/********** SHOW ADD ADS FORM ***************/
$("#show_add_form").toggle(change_to_show,change_to_hide );
/*********************** END *************/



/*********** PRINT EXISTED ADS BLOCKS ************/
//fill_exist = html();
$("#existed_ads").load('<?php echo get_option('home'); ?>/wp-content/plugins/advertizer/print_ads_block.php');

/***** TEMP VARIABLES ******/
var time_man, time_man_cl;
var good=0;

$("#start_date").datepicker();
$("#end_date").datepicker();

$("#time_management").click(function(){
  if (!time_man){
    $("#timing").show(500);
    time_man = 1;
  }else{
    $("#timing").hide(500);
    time_man = null;
  }
  
});  // time management click

$("#limit_clicks").click(function(){

  if (!time_man_cl){
    $("#clicking").show(500);
    time_man_cl = 1;
  }else{
    $("#clicking").hide(500);
    time_man_cl = null;
  }
});   //limit clicks 
  
$("#sumbit_ads").click(function(){
  
  if($("#ads_name").val().length == 0 ){
    $("#ads_name").css('background-color', 'red');
   
    }else{
    good = good +1;
    $("#ads_name").css('background-color', null); 
  }
  
  if($("#ads_url").val().length < 5 ){
      $("#ads_url").css('background-color', 'red');
      }else{
      good = good +1;
      $("#ads_url").css('background-color', null);  
   }
  
  if($("#block_width").val().length == 0 ){
    $("#block_width").css('background-color', 'red');
    }else{
    good = good +1;
    $("#block_width").css('background-color', null);

    } 
          
  if($("#block_height").val().length == 0 ){
    $("#block_height").css('background-color', 'red');
    }else{
    good = good +1;
    $("#block_height").css('background-color', null);

    }
      
  if($("#ads_link_url").val().length < 5 ){
    $("#ads_link_url").css('background-color', 'red');
    }else{
    good = good +1;
    $("#ads_link_url").css('background-color', null);
    
    }
    alert ('good>'+good);
   if(1 == 1){
   
   str =   'ads_name='+$("#ads_name").val()+
           '&ads_url='+$("#ads_url").val()+
           '&block_width='+$("#block_width").val()+
           '&block_height='+$("#block_height").val()+
           '&ads_link_url='+$("#ads_link_url").val()+
           '&new_window='+$("#new_window:checked").val()+
           '&trace_clicks='+$("#trace_clicks:checked").val()+
           '&time_management='+$("#time_management:checked").val()+
           '&start_date='+$("#start_date").val()+
           '&end_date='+$("#end_date").val()+
           '&limit_clicks='+$("#limit_clicks:checked").val()+
           '&click_amount='+$("#click_amount").val();
           
             $.ajax({url: '<? echo get_option('home'); ?>/wp-content/plugins/advertizer/add_ads.php',
    type: "POST",
    data: str, 
    error:  function(msg) {alert("Error Saved: " + msg);}, 
    success: function(msg){ alert("Succ Saved: " + msg);
    $("#clear_fields").click();
    $("#existed_ads").html('');
    $("#existed_ads").load('<?php echo get_option('home'); ?>/wp-content/plugins/advertizer/print_ads_block.php');
    good = 0;
    }           
   
  });   // submit_ads click
   }
  });   // submit_ads click

    
$("#detect_img_size").click(function(){
  
  str = "url_name="+$("#ads_url").val();
  
 if ($("#ads_url").val().length > 10)
$.ajax({url: '<? echo get_option('home'); ?>/wp-content/plugins/advertizer/get_image_size.php',
    type: "POST",
   
    data: str, 
    error:  function(msg) {alert("Error Saved: " + msg);}, 
    success: function(msg){ 
    var obj = jQuery.parseJSON(msg);
    if (obj.width == null)
    alert( 'Image Error!' );
    else {
    $("#block_width").val(obj.width)
    $("#block_height").val(obj.height)
    }

    }
    });
    else
    alert ('Wrong Image URL');
    
    });   // detect img size click
    
$("#update_ads").click(function(){
   
  if($("#ads_name").val().length == 0 ){
    $("#ads_name").css('background-color', 'red');
   
    }else{
    good = good +1;
    $("#ads_name").css('background-color', null); 
  }
  
  if($("#ads_url").val().length < 5 ){
      $("#ads_url").css('background-color', 'red');
      }else{
      good = good +1;
      $("#ads_url").css('background-color', null);  
   }
  
  if($("#block_width").val().length == 0 ){
    $("#block_width").css('background-color', 'red');
    }else{
    good = good +1;
    $("#block_width").css('background-color', null);

    } 
          
  if($("#block_height").val().length == 0 ){
    $("#block_height").css('background-color', 'red');
    }else{
    good = good +1;
    $("#block_height").css('background-color', null);

    }
      
  if($("#ads_link_url").val().length < 5 ){
    $("#ads_link_url").css('background-color', 'red');
    }else{
    good = good +1;
    $("#ads_link_url").css('background-color', null);
    
    }
    alert ('good>'+good);
   if(good == 5){
           
   str =   'id='+$("#upd_id").val()+
           '&ads_name='+$("#ads_name").val()+
           '&ads_url='+$("#ads_url").val()+
           '&block_width='+$("#block_width").val()+
           '&block_height='+$("#block_height").val()+
           '&ads_link_url='+$("#ads_link_url").val()+
           '&new_window='+$("#new_window:checked").val()+
           '&trace_clicks='+$("#trace_clicks:checked").val()+
           '&time_management='+$("#time_management:checked").val()+
           '&start_date='+$("#start_date").val()+
           '&end_date='+$("#end_date").val()+
           '&limit_clicks='+$("#limit_clicks:checked").val()+
           '&click_amount='+$("#click_amount").val();
           
             $.ajax({url: '<? echo get_option('home'); ?>/wp-content/plugins/advertizer/upd_ads.php',
    type: "POST",
    data: str, 
    error:  function(msg) {alert("Error Updating: " + msg);}, 
    success: function(msg){ alert("Updated: " + msg);
    $("#clear_fields").click();
    $("#existed_ads").html('');
    $("#existed_ads").load('<?php echo get_option('home'); ?>/wp-content/plugins/advertizer/print_ads_block.php');
    good = 0;
    change_to_hide()
    }           
   
  });   // upd ads ajax click
   }  
  });   // update ads click  



});

function del_ads(id){
  var str = "id="+id;  
  jQuery.ajax({url: '<? echo get_option('home'); ?>/wp-content/plugins/advertizer/del_ads_block.php',
    type: "POST",
    data: str, 
    error:  function(msg) {alert("Error Saved: " + msg);}, 
    success: function(msg){
    alert(msg);
     if (msg == 'deleted!'){
   
    jQuery("#existed_ads").html('');
 jQuery("#existed_ads").load('<?php echo get_option('home'); ?>/wp-content/plugins/advertizer/print_ads_block.php');

     }
    
    } 
    });          
    


}

function click_ads(id){
  var str = "id="+id;  
  jQuery.ajax({url: '<? echo get_option('home'); ?>/wp-content/plugins/advertizer/click_ads.php',
    type: "POST",
    data: str, 
    error:  function(msg) {alert("Error Saved: " + msg);}, 
    success: function(msg){    alert("Success "+msg);     }  
     });       
} 

function edit_ads(id){
var j = jQuery.noConflict();
//j("#sumbit_ads").val('Update');
//j("#sumbit_ads").attr('id','update_ads');
j("#sumbit_ads").hide();
j("#update_ads").show();
change_to_show();
//list_1
//j("#ads_name").val();

//alert (j("#ads_name_1").html());       
j("#ads_name").val(j("#ads_name_"+id).html());
j("#ads_url").val(j("#ads_url_"+id).html());
j("#block_width").val(j("#block_width_"+id).html());
j("#block_height").val(j("#block_height_"+id).html());
j("#ads_link_url").val(j("#ads_link_url_"+id).html());

if(j("#new_window_"+id).html() == 'Turned On')
j("#new_window").attr('checked',true);

if(j("#trace_clicks_"+id).html() == 'Turned On')
j("#trace_clicks").attr('checked',true);

if(j("#time_management_"+id).html() == 'Turned On'){
j("#timing").show();
j("#time_management").attr('checked',true);
} else {
alert ('ok off'+j("#time_management_"+id).html().lenght);
}


j("#start_date").val(j("#start_date_"+id).html());
j("#end_date").val(j("#end_date_"+id).html());

if(j("#limit_clicks_"+id).html() == 'Turned On'){
j("#clicking").show();
j("#limit_clicks").attr('checked',true);
}

j("#click_amount").val(j("#click_amount_"+id).html());
j("#upd_id").val(id);
           
} 