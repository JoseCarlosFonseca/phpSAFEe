<?php
 /*
File Name: content.php
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

function gBody( $id, $options ) {
	global $galleryurl;
	$body = "";
	$body .= "<div id='container_ajaxgallery_$id' class='ajax_gallery_c' align='center'></div>";
	// Gallery config
	$body .= "<script type='text/javascript'>";
	$body .= "	tb_pathToImage = '". $galleryurl ."/images/loadingAnimation.gif';";
	$body .= "	var config = {";
	$body .= "  gid: $id,";
  $body .= "  id: 'container_ajaxgallery_$id',";
  $body .= "  rows: ". $options['rows'] .","; // Filas
  $body .= "  cols: ". $options['cols'] .","; // Columnas
  $body .= "  thumbsize: ". $options['thumbsize'] .","; // Columnas
  $body .= "  aligntable: '". $options['aligntable'] ."',"; // Alineacion de la table
  $body .= "  pag: ". $options['pag'] .","; // Numero de pagina inicial para el album
  $body .= "  isAlbum: ". $options['isAlbum'] .","; // si se muestra un Album, en caso contrario se muestran los albums
  $body .= "  showPagination: ". $options['showPagination'] .","; // Si se muestra la paginación
  // Don`t modify this
  $body .= "  albums: 'none',";
  $body .= "  album: 'none'";
  $body .="};\n";
  // End config gallery
	$body .= "	var gallery$id = new ajaxgallery( config );";
	$body .= "</script>";
	$body .= "<div id='TB_load1'><img src='".$galleryurl."/js/loadingAnimation.gif'></div>";
	if( $options['isAlbum'] == "true" )
    $body .= "<script type='text/javascript' src='http://picasaweb.google.com/data/feed/api/user/". $options['user'] ."/album/". $options['album'] ."?kind=photo&alt=json-in-script&callback=gallery$id.showAlbum'></script>";
  else
    $body .= "<script type='text/javascript' src='http://picasaweb.google.com/data/feed/api/user/". $options['user'] ."?alt=json-in-script&callback=gallery$id.showAlbums&kind=album'></script>";
	return $body;
}

function ajaxgallery($content=''){
  global $wpdb;
//get_option("ajaxgallery_rows")
  $gItems = $wpdb->get_results("SELECT * FROM $wpdb->options WHERE option_name='agItem'");
  foreach ( $gItems as $gItem )
	{
    $gItemsopc = split( ":", $gItem->option_value );
    $options['user'] = $gItemsopc[0];
    $options['album'] = $gItemsopc[1];
    $options['rows'] = $gItemsopc[2];
    $options['cols'] = $gItemsopc[3];
    $options['aligntable'] = $gItemsopc[4];
    $options['pag'] = $gItemsopc[5];
    $options['isAlbum'] = (trim($options['album']) == "") ? "false" : "true";
    $options['showPagination'] = $gItemsopc[6];
    $options['thumbsize'] = $gItemsopc[7];
    $content = str_replace('[ajax_gallery id='. $gItem->option_id .']', GBody($gItem->option_id, $options), $content);
	}
	return $content;
	/*return str_replace('[ajax_gallery]', GBody(), $content);*/
}

function ag_head()
{
  global $galleryurl;
  print "<link rel='stylesheet' href='$galleryurl/css/thickbox.css' type='text/css' media='screen' />\n";
  print "<link rel='stylesheet' href='$galleryurl/css/gallery.css' type='text/css' media='screen' />\n";
  print "<script type='text/javascript' src='$galleryurl/js/jquery.js'></script>\n";
  print "<script type='text/javascript' src='$galleryurl/js/thickbox.js'></script>\n";
  print "<script type='text/javascript' src='$galleryurl/js/gallery.js'></script>\n";
  
}
?>