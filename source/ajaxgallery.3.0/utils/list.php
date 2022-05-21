<?php
 /*
File Name: options.php
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
include_once(dirname(__FILE__).'/../../../../' .'wp-config.php');
include_once(dirname(__FILE__).'/../../../../' .'wp-includes/wp-db.php');

if( isset( $_GET[ 'delete' ]) && isset( $_GET['gId'] ) ){
  $wpdb->query( "DELETE FROM $wpdb->options WHERE option_name='agItem' and option_id=".$_GET['gId'] );
  echo "<div id='message' class='updated fade'><p><strong>Galeria eliminada</strong></p></div>";
}
?>
<div class="wrap">

<h2>Lista de Galerias</h2>

<table class="widefat">
	<thead>
	<tr>
		<th scope="col"><div style="text-align: center">ID</div></th>
		<th scope="col"><div style="text-align: center">User</div></th>
		<th scope="col"><div style="text-align: center">Album</div></th>
		<th scope="col"><div style="text-align: center">Rows</div></th>
		<th scope="col"><div style="text-align: center">Cols</div></th>
		<th scope="col"><div style="text-align: center">Codigo</div></th>
		<th scope="col"></th>
		<th scope="col"></th>
	</tr>
	</thead>
	<tbody id="the-list">
	<?php
    $gItems = $wpdb->get_results("SELECT * FROM $wpdb->options WHERE option_name='agItem'");
    foreach ( $gItems as $gItem ){
    $options = split( ":", $gItem->option_value );
  ?>
	  <tr id='post-371' class='alternate author-self status-publish'>
		  <th scope="row" style="text-align: center"><?php echo $gItem->option_id;?></th>
			<td><?php echo $options[0]; ?></td>
			<td><?php echo $options[1]; ?></td>
			<td><?php echo $options[2]; ?></td>
			<td><?php echo $options[3]; ?></td>
			<td>[ajax_gallery id=<?php echo $gItem->option_id; ?>]</td>
			<td><a href="admin.php?page=ajaxgallery/utils/options.php&gId=<?php echo $gItem->option_id;?>">Editar</a></td>
			<td><a href="admin.php?page=ajaxgallery/utils/list.php&gId=<?php echo $gItem->option_id;?>&delete">Eliminar</a></td>
		</tr>
	<?php } ?>
	</tbody>
</table>
</div>