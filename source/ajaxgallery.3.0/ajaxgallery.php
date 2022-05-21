<?php
 /*
Plugin Name: ajaxGallery
Plugin URI: http://www.laciudadx.com/trabajos/ajaxgallery
Description: Ajax + Picasa + Thickbox
Author: Sergio Ceron Figueroa
Version: 3.0
Author URI: http://www.laciudadx.com

Copyright (C) 2007 Sergio Ceron F. (http://laciudadx.com)
    
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
$galleryurl = get_settings('siteurl')."/wp-content/plugins/ajaxgallery";
require("utils/content.php");

add_action('admin_menu', 'mt_add_pages');

function mt_add_pages(){
	global $galleryurl;
	// Add a new menu under Options:
	/*add_options_page('Ajax Gallery', 'Ajax Gallery', 8, $galleryurl . '/utils/options.php');*/
	add_menu_page('Lista de Galerias', 'Ajax Gallery', 8, $galleryurl . '/utils/list.php');
	add_submenu_page( $galleryurl . '/utils/list.php', 'Nueva galeria', 'Nueva Galeria', 8, $galleryurl . '/utils/options.php');
}
add_action('the_content', 'ajaxgallery');
add_action('wp_head', 'ag_head');

/*add_option("ajaxgallery_user", "username");
add_option("ajaxgallery_rows",  "4");
add_option("ajaxgallery_cols", "4");
add_option("ajaxgallery_align", "center");*/
?>