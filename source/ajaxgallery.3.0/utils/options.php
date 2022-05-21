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

$thumbsizes = array( "32", "48", "64", "72", "144", "160", "200", "288", "320" );

function filterAlbum( $str ){
  $str = str_replace( " ", "", $str );
  $str = str_replace( ".", "", $str );
  $str = str_replace( ",", "", $str );
  return $str;
}

if( isset( $_POST[ 'save' ]) ){
  $sql = "";
  
  $value = (isset($_POST['user']) && trim($_POST['user']) != ""? $_POST['user']      : "user" ) . ":";
  $value .= (isset($_POST['album']) && trim($_POST['album']) != "" ? filterAlbum($_POST['album'])  : "" ) . ":";
  $value .= (isset($_POST['rows']) && trim($_POST['rows']) != "" ? $_POST['rows']    : "4" ) . ":";
  $value .= (isset($_POST['cols']) && trim($_POST['cols']) != "" ? $_POST['cols']    : "4" ) . ":";
  $value .= (isset($_POST['align']) && trim($_POST['align']) != "" ? $_POST['align']  : "center" ) . ":";
  $value .= (isset($_POST['pag']) && trim($_POST['pag']) != "" ? $_POST['pag']      : "0") . ":";
  $value .= (isset($_POST['showp']) && trim($_POST['showp']) != "" ? $_POST['showp']  : "true") . ":";
  $value .= (isset($_POST['thumbsize']) && trim($_POST['thumbsize']) != "" ? $_POST['thumbsize']  : "160");
  if( isset( $_POST[ 'gId' ] ) ){
    $sql = "UPDATE $wpdb->options SET option_value='$value' WHERE option_name='agItem' and option_id=".$_POST[ 'gId' ];
  }else{
    $sql = "INSERT INTO $wpdb->options (option_name, option_value) VALUES('agItem','$value')";
  }
  $wpdb->query($sql);
  
	if( isset( $_POST[ 'gId' ] ) )
    echo "<div id='message' class='updated fade'><p><strong>Opciones guardadas</strong></p></div>";
  else
    echo "<div id='message' class='updated fade'><p><strong>Galeria creada</strong></p></div>";
}
if( isset( $_GET['gId'] ) || isset( $_POST['gid'] ) ){
  $ggId = isset( $_GET[ 'gId' ]) ? $_GET[ 'gId' ] : $_POST['gId'];
  $gItem = $wpdb->get_row("SELECT * FROM $wpdb->options WHERE option_name='agItem' and option_id=".$ggId);
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
}
?>
<div class="wrap">
<?php
if( isset( $_GET[ 'gId' ]) || isset( $_POST['gId'] ) ){
?>
<h2>Personalizar galeria</h2> 
<?php
}else{
?>
<h2>Nueva galeria</h2> 
<?php
}
?>
<form method="post" style="padding-left:40px"> 
<h3>Opciones de usuario:</h3>
<p>
<label>
<input name="user" type="text" value="<?php echo $options['user'];?>"  /> 
Usuario picasa<br>
Sin @gmail.com ( ej. sxceron )
   </label>
</p>
<p>
<label>
<input name="album" type="text" value="<?php echo $options['album'];?>"  /> 
Album (Opcional)<br>
Sin espacios, ni puntos ( ej. KDE 4.0.0 => KDE400  )
   </label>
</p>


<h3>Galeria</h3>

<p>
<label>
<input name="rows" type="text" value="<?php echo $options['rows'];?>" /> 
Numero de filas [Numero]<br>
Sera el maximo de fotografias que se mostraran verticalmente
   </label>
</p>
<p>
<label>
<input name="cols" type="text" value="<?php echo $options['cols'];?>" /> 
Numero de columnas [Numero]<br> 
Sera el maximo de fotografias que se mostraran horizontalmente
   </label>
</p>
<p>
<label>
<select name='thumbsize'>
  <?php for($i=0; $i < count($thumbsizes); $i++ ){?>
    <option value='<?php echo $thumbsizes[$i];?>' <?php echo ($thumbsizes[$i] == $options["thumbsize"]) ? "selected" : "";?>><?php echo $thumbsizes[$i];?>px</option>
	<?php } ?>
</select>
Thumbnail (imagen) [Numero]<br> 
   </label>
</p>
<p>
<label>
<select name='align'>
	<option value='left' <?php echo ($options['aligntable'] == "left") ? "selected" : "";?>>Izquierda</option>
  <option value='center' <?php echo ($options['aligntable'] == "center") ? "selected" : "";?>>Centrada</option>
  <option value='right' <?php echo ($options['aligntable'] == "right") ? "selected" : "";?>>Derecha</option>
</select>
Alinear la tabla [Texto]<br>
   </label>
</p>
<p>
<label>
<input name="pag" type="text" value="<?php echo $options['pag'];?>"  /> 
Imagen inicial (Opcional) [Numero]
   </label>
</p>
<p>
<label>
<select name='showp' value="<?php echo $options['showPagination'];?>">
	<option value='true' <?php echo ($options['showPagination'] == "true") ? "selected" : "";?>>Si</option>
  <option value='false' <?php echo ($options['showPagination'] == "false") ? "selected" : "";?>>No</option>
</select>
Mostrar paginacion [Booleano]
   </label>
</p>
<?php
if( isset( $_GET[ 'gId' ]) || isset( $_POST['gId'] ) ){
$ggId = isset( $_GET[ 'gId' ]) ? $_GET[ 'gId' ] : $_POST['gId'];
?>
<p>
<label>
<textarea>[ajax_gallery id=<?php echo $ggId;?>]</textarea><br>
Codigo<br>
Copiar y pegar
   </label>
</p>
<input name="gId" type="hidden" value="<?php echo $ggId;?>"  /> 
<?php
}
?>

    <p class="submit"> 
      <input type="submit" name="save" value="Actualizar la galeria &raquo;" /> 
    </p> 
  </form> 
</div>