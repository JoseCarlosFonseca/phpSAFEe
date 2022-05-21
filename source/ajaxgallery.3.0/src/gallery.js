/**
File Name: gallery.js
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

/*
 * Inicializa los albums
 */
function initAlbums( root, gallery ){
	gallery.configs.albums = root;
};

/**
 * Clase general
 * config: Arreglo de configuraciones
 */
function ajaxgallery( config ){
	this.configs = config;
  
/**
 * Muestra las caratulas de los albums publicos
 * Cada album al hacer click lleva a las imagenes del mismo
 * root: Nodo principal de Picasa (JSON)
 */
this.showAlbums = function(root){
	if( root )
    this.configs.albums = root;
	else
    root = this.configs.albums;
    
	var feed = root.feed; 
	var entries = feed.entry || [];
	var pwaFetch = feed.entry.length;
	
	var pwaImageSize = this.configs.thumbsize;; // default image size
	var div = document.getElementById( this.configs.id );
	var table = this.createTable();
	
	for ( i = 0, r = 0, c = 0; i < pwaFetch ; ++i){
		var entry = feed.entry[i];
		var title = entry.title.$t;
		var jsonImage = entry.media$group.media$content[0].url;
		var link = entry.link[1].href;
		var tr = table.getElementsByTagName("tr")[ r ];
		var td = tr.getElementsByTagName( "td" )[ c ];
		
		// Creamos el html dinamicamente
		var vinculo = document.createElement( "a" );
		vinculo.setAttribute( "href", "#" + this.configs.id );
		vinculo.setAttribute( "onclick", "gallery"+this.configs.gid+".loadscript('" + entry.id.$t +"')" ); 
		
    var image = document.createElement( "img" );
    image.src = jsonImage + "?imgmax=" + pwaImageSize + "&crop=1";
    image.setAttribute( "class", "ag_wp_img" );
    vinculo.appendChild( image );
    
    var titulo = document.createElement( "div" );
    titulo.innerHTML = title;
    titulo.setAttribute( "class", "ag_wp_title" );
    
    td.appendChild( vinculo );
    td.appendChild( titulo );
    // Fin del html
		
		if( c == this.configs.cols-1 ){
			if( r >= this.configs.rows-1 )break;
			r++;
			c = 0;
		}else{
			c++;
		}
	}
	div.innerHTML  = div.innerHTML;
	
	// Hide loading messsage
	$('#loading_ajaxgallery').hide();
};

/*
 * Muestra las imagenes de un album especifico
 * La funcion es lanzada automaticamente como callback, 
 *  es por eso que no necesita el nombre o id del album
 * root: Nodo principal de Picasa (JSON)
 * page: Numero de pagina (Paginación)
 */
this.showAlbum = function( root, page ){
	var feed = root.feed; 
	var entries = feed.entry || [];
	var pwaFetch = feed.entry.length;
	
	var pwaImageSize = this.configs.thumbsize; // default image size

	var div = document.getElementById( this.configs.id );
	var table = this.createTable();
	this.configs.album = root;
	this.configs.pag = (typeof page != "undefined"?page:this.configs.pag);
	
	for ( i = this.configs.pag, r = 0, c = 0; i < pwaFetch ; ++i){
		var entry = feed.entry[i];
		var title = entry.title.$t;
		var desc  = entry.media$group.media$description.$t;
		var jsonImage = entry.media$group.media$content[0].url;
		var link = entry.link[1].href;
		var tr = table.getElementsByTagName("tr")[ r ];
		var td = tr.getElementsByTagName( "td" )[ c ];
		var url = jsonImage + "?imgmax=" + 640;
		var url2 = jsonImage + "?imgmax=" +  pwaImageSize;

    // Creamos el html dinamicamente
		var vinculo = document.createElement( "a" );
		vinculo.setAttribute( "href", url );
		vinculo.setAttribute( "title", desc ); 
		vinculo.setAttribute( "class", "thickbox" ); 
		vinculo.setAttribute( "rel", "gallery-album" ); 
		
    var image = document.createElement( "img" );
    image.src = url2;
    image.setAttribute( "class", "ag_wp_img" );
    vinculo.appendChild( image );
    
    var titulo = document.createElement( "div" );
    titulo.setAttribute( "class", "ag_wp_title" );
    
    var linkt = document.createElement( "a" );
    linkt.setAttribute( "href", link );
    linkt.innerHTML = title;
    titulo.appendChild( linkt );
    
    var date = document.createElement( "div" );
    date.setAttribute( "class", "ag_wp_date" );
    date.innerHTML = entry.updated.$t;
    
    td.appendChild( vinculo );
    td.appendChild( titulo );
    td.appendChild( date );
    // Fin del html
    
		if( c == this.configs.cols-1 ){
			if( r >= this.configs.rows-1 )
        break;
			r++;
			c = 0;
		}else{
			c++;
		}
	}
	
	/* Corrige el error de IE al limpiar un DIV */
	div.innerHTML = div.innerHTML;
	
	var gContent   = div.innerHTML;
	var top        = "";
	var bottom     = "";

	if( !this.configs.isAlbum )
    top   += backtoAlbums(this.configs.gid);
  if( this.configs.showPagination )
  	top   += this.Pagination( pwaFetch, root );
  	
	if( this.configs.showPagination )
    bottom += this.Pagination( pwaFetch, root );
	if( !this.configs.isAlbum )
    bottom += backtoAlbums(this.configs.gid);
    
  div.innerHTML = top + gContent + bottom;
	
	tb_init('a.thickbox, area.thickbox, input.thickbox'); // Fix bug, re-inicializa a thickbox
	
	// Ocultamos el mensaje de "cargando...", fix IE
	$('#TB_load1').hide();
};

/**
 * Muestra y administra la paginación de los albums (En caso de que exista)
 * n: Numero total de imagenes
 * root: Nodo principal de Picasa (JSON)
 */
this.Pagination = function ( n, root ){
	var npp = this.configs.cols * this.configs.rows;
	var divn = "<div class='pagination'>";
	for( pag = 0; pag < n; pag += npp ){
		if( pag == this.configs.pag )
			divn += "<a class='pagsel'>" + ((pag/npp)+1) + "</a>";
		else
			divn += "<a class='pag' onclick='gallery"+this.configs.gid+".showAlbum( gallery"+this.configs.gid+".configs.album,"+pag+" )'>" + ((pag/npp)+1) + "</a>";
	}
	return (divn + "</div>");
};

/**
 * Carga dinamicamente un script (.js)
 * Adicionalmente muestra una imagen mientras el objeto es cargado
 * source: Teoricamente la url del script, aunque por ser caso principal es modificada
 */
this.loadscript = function ( source ){
  // show loading message
	$('#TB_load1').show();
		
	var script = document.createElement('script');
	script.type = 'text/javascript';
	
	// When script is loaded (not work on IE)
	script.onload =  function() {
			$('#TB_load1').hide();
	};
	script.src = source.replace( "entry", "feed" ) + "&callback=gallery"+this.configs.gid+".showAlbum&kind=photo";
	document.getElementsByTagName('head')[0].appendChild(script);  
};

/**
 * Crea una tabla de n filas por m columnas
 * No requiere parametros, esos son pasados directamente desde las configuraciones
 */
this.createTable = function (){

	div = document.getElementById( this.configs.id );
	this.clean( div );
	var table = document.createElement( "table" );
	table.setAttribute( "align", this.configs.aligntable );
	for( row = 0; row < this.configs.rows; row++ )
	{
		var tr = document.createElement( "tr" );
		for( col = 0; col < this.configs.cols; col++ )
		{
			var td = document.createElement( "td" );
			tr.appendChild( td );
		}

		table.appendChild( tr );
	}
	div.appendChild( table );
	return table;
};

/*
 * Limipia el contenedor principal
 * div: id del objeto donde se encuentra contenida la galeria
 */
this.clean = function ( div ){
	div.innerHTML = "";
};
};

/*
 * Funcion extra: Muestra el vinculo para regresar a los albums
 */
function backtoAlbums(gid){
	return "<div align='center'><a class='linkw' onclick='gallery"+gid+".showAlbums();'>Ver albums</a></div>"
};
