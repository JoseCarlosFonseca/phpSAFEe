<?php

/**
 * User: pnunes
 * Date: 15/04/16
 * Time: 22:05
 */

 if (isset($_GET['source_dir'])) {
	$source_dir = $_GET['source_dir'];
} else {
	if ($argc < 2) {
		die ("\n\nUsage: php phpSAFE <source_dir>\n\n");
	} else
		$source_dir = $argv[1];
		echo "Project: $source_dir\n";
}

require "config.php";
require "phpSAFE_class_RunTool.php";
	
$tool = new RunTool($input_dir, $output_dir, $source_dir, $VULNERABILITY_CLASSES_TO_REPORT);
$r_array = $tool->PluginListOfFiles();  // list_of_file, html
$php_file_list = $r_array[0];

echo "<h1>Project: $source_dir <br>Files: " . count($php_file_list) . '</h1>';

$tool->run($php_file_list);

