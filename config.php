<?php

/**
 * User: pnunes
 * Date: 16-04-2016
 * Time: 17:43
 */
 
 if (isset($_SERVER['SERVER_PORT'])) {
	$port = $_SERVER['SERVER_PORT'];
	$base_url = "http://" . $_SERVER['SERVER_NAME'] . ":$port" . dirname($_SERVER["REQUEST_URI"]) . '/';
} else {
	$base_url ="";
}	

if (!defined('BASE_URL')) {
    define('BASE_URL', $base_url);
}

$input_dir = "source";   // without final /
$output_dir = "output";

$VULNERABILITY_CLASSES_TO_REPORT = array("SQL Injection", "Possible SQL Injection", "Cross Site Scripting", "Possible Cross Site Scripting");

//$VULNERABILITY_CLASSES_TO_REPORT = array("SQL Injection", "Possible SQL Injection");
//$VULNERABILITY_CLASSES_TO_REPORT = array("Cross Site Scripting", "Possible Cross Site Scripting");

