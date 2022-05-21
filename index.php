<style>
    table, td, th {
        padding: 4px;
        border: 1px solid gray;
        border-collapse: collapse;
    }
</style>
<?php
/**
 * User: pnunes
 * Date: 15/04/16
 * Time: 22:05
 */
require 'config.php';
require "phpSAFE_class_RunTool.php";
$path = $input_dir;
$dir = opendir($path . "/");


$html = "<table><tr><th>Dir</th><th>Files/#Files</th><th>Browser: run phpSAFE</th><th>sh: run phpSAFE</th></tr>";
while ($item = readdir($dir)) {
    if ($item == ".")
        continue;
    if ($item == "..")
        continue;
    $sub = $path . '/' . $item;
    if (is_dir($sub)) {
        $path2 = $sub . '/';
        $html .= "<tr><td>$sub</td></td>";

        $i = 0;
        $php_file_list = array();
        $files = "<table id='id_{$item}' style='display:none;'>";
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path2)) as $file_name) {
            if ($file_name->isDir())
                continue;
			//echo $file_name;
			$aux = explode('.', $file_name);
            $ext = end($aux);
            if ($ext != "php")
                continue;
            $i++;
            $file_name = str_replace("\\", '/', $file_name);
            $initial_file_name = substr($file_name, strlen($path) + 1);
            $link = "<a href='show_source_file.php?file=$file_name'>$file_name</a>";
            $files .= "<tr><td>$i</td><td>$link</td></tr>";
        }
        $files .= "</table>";
        $script = "php phpSAFE.php source_dir=$item > output.html";
        $link = "<a target='_blank' href='phpSAFE.php?source_dir=$item'>$item</a>";
        $x = "<span id='s_{$item}' onclick=\"var o = document.getElementById('id_{$item}'); if (o.style.display == 'block') {o.style.display = 'none'; document.getElementById(this.id).innerHTML = 'Show';} else { o.style.display = 'block';document.getElementById(this.id).innerHTML = 'Hide';}\" style='border:1px solid black;padding:1px;background-color:#eee;'>Show</span>";
        $html .= "<td>$x $i <br> $files</td><td>$link</td></td><td>$script</td></tr>";
    }
}
$html = "<h1>phpSAFEe - PHP Security Analysis For Everyone: multiple projects</h1>" . $html . "</table>";
echo $html;

