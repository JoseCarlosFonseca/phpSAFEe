<style>
    table, td, th {
        padding: 4px;
        border: 1px solid gray;
        border-collapse: collapse;
    }
</style>

<?php
/**
 *
 * phpSAFEe - PHP Security Analysis For Everyone
 *
 * Copyright (C) 2013 by Jose Fonseca (jozefonseca@gmail.com)
 * Copyright (C) 2021 by Paulo Nunes (pnunes100@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * Wherever third party code has been used, credit has been given in the code's
 * comments.
 *
 * phpSAFE is released under the GPL
 */
include "class-php-safe.php";

class RunTool {

    public $input_dir;
    public $output_dir;
    public $output_dir_base;
    public $plugin;
    //private $VULNERABILITY_CLASSES_TO_REPORT = array("unknown", "SQL Injection", "Possible SQL Injection", "Cross Site Scripting", "Possible Cross Site Scripting");
    //private $VULNERABILITY_CLASSES_TO_REPORT_1 = array("unknown", "SQL Injection", "Possible SQL Injection", "Cross Site Scripting", "Possible Cross Site Scripting");
    //private $VULNERABILITY_CLASSES_TO_REPORT = array ("SQL Injection", "Possible SQL Injection");
    private $VULNERABILITY_CLASSES_TO_REPORT = array();

    function RunTool($input_dir, $output_dir, $source_dir, $VULNERABILITY_CLASSES_TO_REPORT) {
        $this->VULNERABILITY_CLASSES_TO_REPORT = $VULNERABILITY_CLASSES_TO_REPORT;
        $this->input_dir = $input_dir . '/' . $source_dir;
        $this->output_dir = $output_dir;
        $this->output_dir_base = $output_dir;
        $this->plugin = $source_dir;

        if (!is_dir($this->output_dir)) {
            mkdir($this->output_dir);
        }
        if (!is_dir($this->output_dir)) {
            mkdir($this->output_dir);
        }
        $this->output_dir .= "/{$this->plugin}";
        if (!is_dir($this->output_dir)) {
            mkdir($this->output_dir);
        }
        $this->output_dir .= "/";
    }

    public function PluginListOfFiles() {
        $path2 = $this->input_dir . '/';
        $html = "<table><tr><td colspan='10'><h2>$path2</h2></td></tr>";
        $html .= "<tr><td>$this->plugin</td></tr>";

        $file_name_txt = $this->output_dir . $this->plugin . ".txt";
        $f = fopen($file_name_txt, "wt");
        $files = ''; // '$php_file_list' . " = array(\n";
        $html = "";
        $i = 0;
        $php_file_list = array();
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path2)) as $file_name) {
            if ($file_name->isDir())
                continue;
            $file_name = str_replace("\\", '/', $file_name);
            //$ext = end(explode('.', $file_name)); 
            $ext = explode('.', $file_name);
            $ext = end($ext);
            if ($ext != "php")
                continue;

            $initial_file_name = substr($file_name, strlen($this->input_dir) + 1);
            $html .= "<tr><td>$initial_file_name</td><td>$file_name</td></tr>";
            $files .= "'$file_name',\n";

            $i++;
            //echo "$i - " . $file_name . '<br />';
            $php_file_list [] = $file_name;
        }
        $files = substr($files, 0, strlen($files) - 2);
        fprintf($f, "%s", "$files");
        fclose($f);
        $html .= "</table>";

        return array($php_file_list, $html);
    }

    public function run($php_file_list) {
        $path_files = '';
        echo "<h2>" . APP . "</h2>";
        if (extension_loaded('tokenizer') === false) {
            echo 'The PHP tokenizer extension must be enabled';
            exit;
        }

        ini_set('memory_limit', -1); //-1 unlimited
        set_time_limit(0); //0 unlimited execution time

        $s = date('Y-m-d_H_i_s', time());
        $s = '-' . gethostname() . "_";

        $BASE_URL_VAR = BASE_URL;

        $jquery = <<<_END
				<script src='{$BASE_URL_VAR}jquery.js'/>
				<script src='../../jquery.js'/>
      <script>
         $(document).ready(function() {
        $("td").mouseover(function() {
          if (this.innerText)
             $("td:contains(" + this.innerText + ")").css("background-color", "orange");
        });
        $("td").mouseout(function() {
          if (this.innerText)
            $("td:contains(" + this.innerText + ")").css("background-color", "white");
        });
        $("th").mouseover(function() {
          if (this.innerText)
           $("th:contains(" + this.innerText + ")").css("background-color", "orange");
        });
        $("th").mouseout(function() {
          if (this.innerText)
            $("th:contains(" + this.innerText + ")").css("background-color", "white");
        });
      });
      </script>
_END;

        $initial_parsed_file_length_cut = strlen($this->input_dir) + 1;
        $href_html = $this->output_dir . "output.html";
        $href_csv = $this->output_dir . "vulnerabilities.csv";
        //$href_csv_add = $this->output_dir_base . "/vulnerabilities_add.csv";
        $href_csv_non = $this->output_dir . "non-vulnerabilities.csv";
        //$href_csv_add_non = $this->output_dir_base . "/non-vulnerabilities_add.csv";
        $href_sql = $this->output_dir . "vulnerabilities.sql";
        $href_sql2 = $this->output_dir . "vulnerabilities_resume.sql";

        $output_file = fopen($href_html, 'wt') or die("Failed to create file");
        $csv_file = fopen($href_csv, 'w') or die("Failed to create file");
        $csv_file_non = fopen($href_csv_non, 'w') or die("Failed to create file");
        //$csv_file_add = fopen($href_csv_add, 'a') or die("Failed to create file");
        //$csv_file_add_non = fopen($href_csv_add_non, 'a') or die("Failed to create file");

        $csv_text = 'PHP_PLUGIN;PHPI_FILE_BASE;PHPI_FILE_AND_DIR;PHPI_INDEX;PHPI_NAME;PHPI_OBJECT;PHPI_CLASS;PHPI_SCOPE;PHPI_VARIABLE_FUNCTION;PHPI_EXIST_DESTROYED;PHPI_CODE_TYPE;PHPI_INPUT;PHPI_OUTPUT;PHPI_FUNCTION;PHPI_FILE;PHPI_LINE;PHPI_TAINTED;PHPI_VULNERABILITY;PHPI_START_INDEX;PHPI_END_INDEX;PHPI_DEPENDENCIES_INDEX;PHPI_VARIABLE_FILTER;PHPI_VARIABLE_REVERT_FILTER;PHPI_SENSITIVE_SINK;PHPI_SENSITIVE_SINK_VULNERABILITY;Data;Manually_verified;Link;piece_of_code;execution_time;memory';
        $csv_text = str_replace(" ", "", $csv_text);
        fprintf($csv_file, "%s\n", $csv_text) or die("Could not write to file");
        fprintf($csv_file_non, "%s\n", $csv_text) or die("Could not write to file");

        $sql_file = fopen($href_sql, 'w') or die("Failed to create file");
        $sql_file2 = fopen($href_sql2, 'w') or die("Failed to create file");
        //write the csv file with the vulnerability data
        $out2 = "<h1>Test was done on $s</h1>";

        echo "<p><a href='./$this->output_dir'>Browser results: $this->output_dir</a></p>";

        echo $jquery;
        //echo $out2;
        fprintf($output_file, "%s\n", "$out2 \n $jquery \n<table>") or die("Could not write to file");
        $output_text = "<style>table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>";
        $output_text .= "<tr><td>#</td>";
        $output_text .= "<td>plugin</td>";
        $output_text .= "<td>parsed_file_ini</td>";
        $output_text .= "<td>parsed_file</td>";
        $output_text .= "<td>Total Vulns</td>";
        $output_text .= "<td>XSS</td>";
        $output_text .= "<td>SQLi</td>";
        $output_text .= "<td>time</td>";
        $output_text .= "<td>value</td>";
        $output_text .= "<td>#files</td>";
        $output_text .= "<td>SLOC</td>";
        $output_text .= "</tr>";
        fprintf($output_file, "%s\n", $output_text) or die("Could not write to file");
        fflush($output_file);

        echo "<table><tr><th>#</th>  <th>Vulnerabilities</th>   <th>Time</th>    <th>File</th>  <th>Files</th>  <th>LOC</th>
				<th>Memory usage (kB)</th>
				<th>#Parser</th>
				<th>#Output</th>
				

				<th>Table of Vuln.</th>
				<th>Vuln. Variable dependencies</th>
				<th>Output</th>
				<th>Non-vuln</th>
				
				</tr>";
        
       // <th>Total</th>
	// <th>SQLi</th>
	// <th>XSS</th>
        
        $i = 1;
        $a = "";
        $count_diferences = 0;

        $total_num_vulnerabilities = 0;
        $total_num_vulnerabilities_XSS = 0;
        $total_num_vulnerabilities_SQLi = 0;
        $total_time = 0;
        $more = 0;
        $less = 0;
        $flag1 = $flag2 = 0;
        $num_non_vulnerabilities = $num_parser_variables = 0;
        foreach ($php_file_list as $value) {
            $parsed_file = substr($value, $initial_parsed_file_length_cut);
            $parsed_file_ini = $parsed_file;
            $parsed_file_ini_basename = basename($value);

            $value = $path_files . $value;
            $value = trim($value);
            $num_vulnerabilities = 0;
            $time_start = microtime(true);
            $memory = intval(memory_get_usage() / 1024.0);


            // ############## scan for vulnerabilities #####################################
            $vulnerability_check = new PHP_SAFE(htmlspecialchars((string) $value));


            $num_vulnerabilities = count($vulnerability_check->get_vulnerable_variables());
            $num_non_vulnerabilities += is_array(($vulnerability_check->get_non_vulnerable_variables())) ? count($vulnerability_check->get_non_vulnerable_variables()):0;
            $num_parser_variables += is_array(($vulnerability_check->get_parser_variables()))? count($vulnerability_check->get_parser_variables()):0;
            $num_parser_variables_file = is_array(($vulnerability_check->get_parser_variables())) ? count($vulnerability_check->get_parser_variables()):0;
            $num_output_variables = is_array(($vulnerability_check->get_parser_variables())) ? count($vulnerability_check->get_parser_variables()):0;
            $memory = intval(memory_get_usage() / 1024.0) - $memory;
            $total_num_vulnerabilities += $num_vulnerabilities;
            $time = microtime(true) - $time_start;
            $total_time += $time;

            $files_include_require = $vulnerability_check->get_files_include_require();
            //var_dump($files_include_require);
            if (0 < is_array($files_include_require)?count($files_include_require):0) {
                foreach ($files_include_require as $key => $file) {
                    $f1 = $file['include_require_file_name'];
                    $f1 = str_replace("\\", "/", $f1);
                    if (in_array($f1, $php_file_list)) {
                        echo '<b>' . $file['include_require_file_name'] . '</b> already parsed in <b>' . $value . '</b><br />';
                        //continue 2;
                    }
                }
            }
            $count_files = is_array(($php_file_list)) ? count($php_file_list):0;

            $f_tokens = $vulnerability_check->get_files_tokens();
            $num_files = is_array (($vulnerability_check->get_files_tokens()))? count($vulnerability_check->get_files_tokens()):0;
            $num_lines_of_code = 0;
            if (isset($f_tokens)) {
                foreach ($f_tokens as $file_name => $dummy) {
                    $last_line = 0;
                    $j = count($f_tokens[$file_name]) - 1;
                    while (($j >= 0) && (!is_array($f_tokens[$file_name][$j]))) {
                        $j--;
                    }
                    $last_line = $f_tokens[$file_name][$j][2];

                    $num_lines_of_code = $num_lines_of_code + $last_line;
                }
            }

            $bold = "";
            $bold_time = "";
            $vul = "";
            $num_vulnerabilities_SQLi = 0;
            $num_vulnerabilities_XSS = 0;
            $vulnerable_file = '';

            //if ($num_vulnerabilities == 0) {
            //   $csv_text = "{$this->plugin};$parsed_file_ini;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1";
            //fprintf($csv_file_add, "%s\n", $csv_text) or die("Could not write to file");
            // } else if ($num_vulnerabilities > 0) {
            $bold = "font-weight: bold;";

            // get_vulnerable_variables | get_non_vulnerable_variables
            for ($type = 0; $type < 2; $type++) {
                if ($type == 0) {
                    $typeV = $vulnerability_check->get_vulnerable_variables();
                    $csv_file_aux = $csv_file;
                    //$csv_file_add_aux = $csv_file_add;
                } else {
                    $typeV = $vulnerability_check->get_non_vulnerable_variables();
                    $csv_file_aux = $csv_file_non;
                    //$csv_file_add_aux = $csv_file_add_non;
                }
                if (count($typeV) == 0) {
                    $csv_text = "{$this->plugin};$parsed_file_ini;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1;-1";
                    fprintf($csv_file, "%s\n", $csv_text) or die("Could not write to file");
                } else {
                    foreach ($typeV as $key => $var0) {
                        if (in_array($var0[_PHPI_VULNERABILITY], $this->VULNERABILITY_CLASSES_TO_REPORT)) {

                            if (($flag1 == 0) || ($flag2 == 0)) {
//                                if ($type==0) $flag1 = 1;
//                                if ($type==1) $flag2 = 1;
//                                $csv_text = 'PHP_PLUGIN; PHPI_FILE_BASE; PHPI_FILE_AND_DIR; PHPI_INDEX; PHPI_NAME; PHPI_OBJECT; PHPI_CLASS; PHPI_SCOPE; PHPI_VARIABLE_FUNCTION; PHPI_EXIST_DESTROYED; PHPI_CODE_TYPE; PHPI_INPUT; PHPI_OUTPUT; PHPI_FUNCTION; PHPI_FILE; PHPI_LINE; PHPI_TAINTED; PHPI_VULNERABILITY;PHPI_START_INDEX;PHPI_END_INDEX; PHPI_DEPENDENCIES_INDEX; PHPI_VARIABLE_FILTER; PHPI_VARIABLE_REVERT_FILTER; Data; Manually_verified; Link; piece_of_code; execution_time; memory';
//                                $csv_text = str_replace(" ", "", $csv_text);
//                                fprintf($csv_file_aux, "%s\n", $csv_text) or die("Could not write to file");
                            }
                            $vulnerable_file_full_name = $vulnerability_check->files->files_tokens_names[intval($var0[_PHPI_FILE])];
                            $vulnerable_file = substr($vulnerability_check->files->files_tokens_names[intval($var0[_PHPI_FILE])], $initial_parsed_file_length_cut);
                            $vulnerable_file = str_replace("\\", "/", $vulnerable_file);
                            $csv_text = $this->plugin . ';' . $parsed_file_ini . ';' . $vulnerable_file . ';';

                            // piece of code
                            $name = $var0[_PHPI_NAME];
                            $line = $var0[_PHPI_LINE];
                            $tainted = $var0[_PHPI_TAINTED];
                            $cor = ($tainted === 'tainted') ? 'red' : 'green' . "; background-color: lightpink;";
                            $file_name = $vulnerability_check->files->files_tokens_names [$var0[_PHPI_FILE]];
                            $piece_of_code = $vulnerability_check->get_lines_of_code($file_name, $name, $line, -6, $cor);
                            //$piece_of_code = addslashes($piece_of_code[1]);
                            $piece_of_code = str_replace(";", "#", $piece_of_code[1]);

                            foreach ($var0 as $k => $v) {
                                if (!is_array($v)) {
                                    $csv_text .= $v . ';';
                                } else {
                                    $NN = count($v) - 1;
                                    $II = 0;
                                    foreach ($v as $v2) {
                                        $variable_name_dep = $vulnerability_check->get_parser_variables()[$v2];
                                        $variable_name_dep = $variable_name_dep[_PHPI_LINE];
                                        $csv_text .= $variable_name_dep;
                                        if ($II < $NN)
                                            $csv_text .= ',';
                                        $II++;
                                    }
                                    $csv_text .= ';';
                                }
                            }

                            $text = "123";
                            $variable = $var0;
                            $variable_name = $variable[_PHPI_NAME];

                            if (isset($variable[_PHPI_START_LINE]))
                                $line_mark = $variable[_PHPI_START_LINE];
                            elseif (isset($variable[_PHPI_LINE]))
                                $line_mark = $variable[_PHPI_LINE];
                            else
                                $line_mark = 0;

                            if (isset($variable[_PHPI_END_LINE]))
                                $line_end = $variable[_PHPI_END_LINE];
                            else
                                $line_end = $line_mark - 1;
                            $variable_name = str_replace(array('$', "'", '"'), array('%24', '%27', '%22'), $variable_name);
                            $value_link = BASE_URL . "show_php_file.php?file=$vulnerable_file_full_name&line_mark=$line_mark&line_end=$line_end&variable_name=" . $variable_name . "&text=$text#target_mark";

                            $csv_text .= date('Y-m-d H:i:s', time()) . ";";
                            $csv_text .= '0' . ";";
                            $csv_text .= $value_link . ";";
                            $csv_text .= $piece_of_code . ";";
                            $csv_text .= $time . ";";
                            $csv_text .= $memory . ";";


                            $csv_text = substr($csv_text, 0, strlen($csv_text) - 1);
                            fprintf($csv_file_aux, "%s\n", $csv_text) or die("Could not write to file");
                            // fprintf($csv_file_add_aux, "%s\n", $csv_text) or die("Could not write to file");

                            $sql_insert = "'" . $this->plugin . "','" . $parsed_file_ini . "','" . $vulnerable_file . "',";
                            // $sql_insert .=  "'" .$var0[_PHPI_FILE_BASE]. "'," ;
                            //$sql_insert .=  "'" .$var0[_PHPI_FILE_AND_DIR]. "'," ;

                            $sql_insert .= "'" . $var0[_PHPI_INDEX] . "',";
                            $sql_insert .= "'" . $var0[_PHPI_NAME] . "',";
                            $sql_insert .= "'" . $var0[_PHPI_OBJECT] . "',";
                            $sql_insert .= "'" . $var0[_PHPI_CLASS] . "',";
                            $sql_insert .= "'" . $var0[_PHPI_SCOPE] . "',";
                            $sql_insert .= "'" . $var0[_PHPI_VARIABLE_FUNCTION] . "',";
                            $sql_insert .= "'" . $var0[_PHPI_EXIST_DESTROYED] . "',";
                            $sql_insert .= "'" . $var0[_PHPI_CODE_TYPE] . "',";
                            $sql_insert .= "'" . $var0[_PHPI_INPUT] . "',";
                            $sql_insert .= "'" . $var0[_PHPI_OUTPUT] . "',";
                            $sql_insert .= "'" . $var0[_PHPI_FUNCTION] . "',";
                            $sql_insert .= "'" . $vulnerable_file . "',";
                            $sql_insert .= "'" . $var0[_PHPI_LINE] . "',";
                            $sql_insert .= "'" . $var0[_PHPI_TAINTED] . "',";
                            $sql_insert .= "'" . $var0[_PHPI_VULNERABILITY] . "',";
                            $sql_insert .= "'" . $var0[_PHPI_START_INDEX] . "',";
                            $sql_insert .= "'" . $var0[_PHPI_END_INDEX] . "',";

                            if (isset($var0[_PHPI_DEPENDENCIES_INDEX])) {
                                $v = $var0[_PHPI_DEPENDENCIES_INDEX];
                                if (is_array($v)) {
                                    $sql_insert .= "'";
                                    foreach ($v as $ii) {
                                        $sql_insert .= $ii . " ";
                                    }
                                    $sql_insert .= "',";
                                } else {
                                    $sql_insert .= "'" . $v . "',";
                                }
                            } else {
                                $sql_insert .= "'" . '' . "',";
                            }

                            if (isset($var0[_PHPI_VARIABLE_FILTER])) {
                                $v = $var0[_PHPI_VARIABLE_FILTER];
                                if (is_array($v)) {
                                    $sql_insert .= "'";
                                    foreach ($v as $ii) {
                                        $sql_insert .= $ii . " ";
                                    }
                                    $sql_insert .= "',";
                                } else {
                                    $sql_insert .= "'" . $v . "',";
                                }
                            } else {
                                $sql_insert .= "'" . '' . "',";
                            }

                            if (isset($var0[_PHPI_VARIABLE_REVERT_FILTER])) {
                                $v = $var0[_PHPI_VARIABLE_REVERT_FILTER];
                                if (is_array($v)) {
                                    $sql_insert .= "'";
                                    foreach ($v as $ii) {
                                        $sql_insert .= $ii . " ";
                                    }
                                    $sql_insert .= "',";
                                } else {
                                    $sql_insert .= "'" . $v . "',";
                                }
                            } else {
                                $sql_insert .= "'" . '' . "',";
                            }
                            $sql_insert .= "'" . date('Y-m-d H:i:s', time()) . "',";
                            // Manually_verified
                            $sql_insert .= "'" . '0' . "',";
                            $sql_insert .= "'" . $value_link . "',";
                            $sql_insert .= "'" . $piece_of_code . "',";
                            $sql_insert .= "'" . $time . "',";
                            $sql_insert .= "'" . $memory . "',";

                            $sql_insert = substr($sql_insert, 0, strlen($sql_insert) - 1);
                            $sql_insert = "INSERT INTO vulnerabilities_phpSAFE(PHPI_PLUGIN, PHPI_FILE_BASE,PHPI_FILE_AND_DIR,PHPI_INDEX,PHPI_NAME,PHPI_OBJECT,PHPI_CLASS,PHPI_SCOPE,PHPI_VARIABLE_FUNCTION,PHPI_EXIST_DESTROYED,PHPI_CODE_TYPE,PHPI_INPUT,PHPI_OUTPUT,PHPI_FUNCTION,PHPI_FILE,PHPI_LINE,PHPI_TAINTED,PHPI_VULNERABILITY,PHPI_START_INDEX,PHPI_END_INDEX,PHPI_DEPENDENCIES_INDEX,PHPI_VARIABLE_FILTER,PHPI_VARIABLE_REVERT_FILTER, Data,Manually_verified, link, piece_of_code, execution_time,memory ) VALUES($sql_insert );";
                            fprintf($sql_file, "%s\n", $sql_insert) or die("Could not write to file");
                            if (($var0[_PHPI_VULNERABILITY] == "SQL Injection") || ($var0[_PHPI_VULNERABILITY] == "Possible SQL Injection")) {
                                $num_vulnerabilities_SQLi++;
                                $total_num_vulnerabilities_SQLi++;
                            } else if (($var0[_PHPI_VULNERABILITY] == "Cross Site Scripting") || ($var0[_PHPI_VULNERABILITY] == "Possible Cross Site Scripting")) {
                                $num_vulnerabilities_XSS++;
                                $total_num_vulnerabilities_XSS++;
                            }
                        }
                    }
                    fflush($csv_file_aux);
                    //fflush($csv_file_add_aux);
                    fflush($sql_file);
                }
            }

            $output_text = "<tr><td>$i</td>";
            $output_text .= "<td>" . $this->plugin . "</td>";
            $output_text .= "<td>$parsed_file_ini</td>";
            $output_text .= "<td>$vulnerable_file</td>";
            if ($num_vulnerabilities) {
                $output_text .= "<td style='color:red'>$num_vulnerabilities</td>";
            } else {
                $output_text .= "<td>$num_vulnerabilities</td>";
            }
            //$output_text .= "<td>$num_vulnerabilities_XSS</td>";
            //$output_text .= "<td>$num_vulnerabilities_SQLi</td>";
            $output_text .= "<td>" . sprintf('%11.3f', $time) . "</td>";
            $output_text .= "<td>$value</td>";
            $output_text .= "<td>$num_files</td>";
            $output_text .= "<td>$num_lines_of_code</td></tr>";
            fprintf($output_file, "%s\n", $output_text) or die("Could not write to file");
            fflush($output_file);

            // table two - resume times, total, vulnerabilities
            $sql_insert = "'" . $this->plugin . "',";
            $sql_insert .= "'" . $parsed_file_ini . "',";
            $sql_insert .= "'" . $vulnerable_file . "',";
            $sql_insert .= "'" . sprintf('%d', $i) . "',";
            $sql_insert .= "'" . sprintf('%d', $num_vulnerabilities) . "',";
            $sql_insert .= "'" . sprintf('%d', $num_vulnerabilities_XSS) . "',";
            $sql_insert .= "'" . sprintf('%d', $num_vulnerabilities_SQLi) . "',";
            $sql_insert .= "'" . sprintf('%.4f', $time) . "',";
            $sql_insert .= "'" . sprintf('%d', $memory) . "',";
            $sql_insert .= "'" . $num_files . "',";
            $sql_insert .= "'" . $num_lines_of_code . "',";
            $sql_insert .= "'" . date('Y-m-d H:i:s', time()) . "'";

            $sql_insert = "INSERT INTO vulnerabilities_phpSAFE_resume(PHPI_PLUGIN, PHPI_FILE_BASE,PHPI_FILE_AND_DIR,PHPI_INDEX_FILE,NUM_VULNERABILITIES,NUM_VULNERABILITIES_XSS,NUM_VULNERABILITIES_SQLi,PHPI_TIME,MemoryUsage,NUM_FILES, SLOC, Data) VALUES($sql_insert );";
            fprintf($sql_file2, "%s\n", $sql_insert) or die("Could not write to file");
            fflush($sql_file2);

            $s2 = "";
            //if ($bold != "") {
            $s = "";
            /* if ($av[$i] != $num_vulnerabilities) {
              if ($av[$i] > $num_vulnerabilities) {
              $less++;
              $s = "color:red;";
              }

              if ($av[$i] < $num_vulnerabilities) {
              $more++;
              $s = "color:blue;";
              }
              $count_diferences++;

              $s2 = sprintf(' / %02d', $av[$i]);
              } */
            $bold = "style='$bold;$s'";
            //}
            $output_html = "<tr>";
            $s = sprintf('%03d  ', ($i));
            $output_html .= "<td $bold>$s</td>";

            $s = sprintf('%02d', $num_vulnerabilities);
            $s .= $s2;
            $output_html .= "<td $bold>$s</td>";
            $a .= "$num_vulnerabilities,";

            if ($time > 1) {
                $s = '<b>' . sprintf('%01.2f', $time) . "</b>";
            } else {
                $s = sprintf('%01.2f', $time);
            }

            $link = '';
            $link2 = '';
            $len_link = 0;
            if ($num_vulnerabilities > 0) {
                $link = $vulnerability_check->show_vulnerable_variables($parsed_file_ini, $this->output_dir . str_replace("/", "_", $parsed_file) . '_' . $i);
                $len_link = strlen($link[1]); // .  $link[1];
                $link = $link[0];

                $link = substr($link, strlen($this->output_dir));
                // QTS, VOD
                // $link = "<a href='../$this->output_dir2/$this->plugin/$link'>$link</a>";
                // Macbook
                $link = "<a href='./$this->output_dir$link'>$link</a>";

                //echo $link[1];
                $link2 = $vulnerability_check->show_vulnerable_variables_with_dependencies($parsed_file_ini, $this->output_dir . str_replace("/", "_", $parsed_file) . '_' . $i);
                $link2 = substr($link2, strlen($this->output_dir));
                $link2 = "<a href='./$this->output_dir$link2'>$link2</a>";
            }

            $output_html .= "<td $bold>$s</td>";
            $s = str_replace($path_files . "__", "", $value);
            $output_html .= "<td $bold>$s</td>";
            $output_html .= "<td $bold>$num_files</td>";
            $output_html .= "<td $bold>$num_lines_of_code</td>";
            $output_html .= "<td $bold>$memory</td>";

            $output_html .= "<td $bold>$num_parser_variables_file</td>";
            $output_html .= "<td $bold>$num_output_variables</td>";


            $SQLi_span = $num_vulnerabilities_SQLi;
            if ($num_vulnerabilities_SQLi > 0) {
                $SQLi_span = "<span style='color:red; font-weight: bold'>$num_vulnerabilities_SQLi</span>";
            }
            //$output_html .= "<td $bold>$num_vulnerabilities</td>";
            //$output_html .= "<td $bold>$num_vulnerabilities_XSS</td>";
            //$output_html .= "<td $bold>$num_vulnerabilities_SQLi</td>";

            $output_html .= "<td $bold>$link</td>";
            $output_html .= "<td $bold>$link2</td>";

            $link3 = $vulnerability_check->show_output_variables($parsed_file_ini, $this->output_dir . str_replace("/", "_", $parsed_file) . '_' . $i);
            //$link3 [0] = '';
            $link3 = $link3 [0];
            $link3 = substr($link3, strlen($this->output_dir));
            $link3 = "<a href='./$this->output_dir$link3'>$link3</a>";
            $output_html .= "<td $bold>$link3</td>";

            $link4 = $vulnerability_check->show_non_vulnerable_variables($parsed_file_ini, $this->output_dir . str_replace("/", "_", $parsed_file) . '_' . $i);
            //$link4 [0] = '';
            $link4 = $link4 [0];
            $link4 = substr($link4, strlen($this->output_dir));
            $link4 = "<a href='./$this->output_dir$link4'>$link4</a>";
            $output_html .= "<td $bold>$link4</td>";

            $output_html .= "</tr>";
            echo $output_html;

            //$vulnerability_check->show_used_functions($parsed_file_ini, $this->output_dir . str_replace("/", "_", $parsed_file) . '_' . $i);
            $vulnerability_check->show_file_functions2($parsed_file_ini, $this->output_dir . str_replace("/", "_", $parsed_file) . '_' . $i);
            //$vulnerability_check->show_file_functions($parsed_file_ini, $this->output_dir . str_replace("/", "_", $parsed_file) . '_' . $i);
            //$html_file_name = realpath(dirname(__FILE__)) . DIRECTORY_SEPARATOR . basename(__FILE__);
            //echo "http://".$_SERVER['SERVER_NAME'].'    ---------------    ' .dirname($_SERVER["REQUEST_URI"].'?').'/';
            // $vulnerability_check->show_resume_report($this->output_dir . "resume_" . $parsed_file_ini . '.html');
            /* $vulnerability_check->show_tokens_array_of_arrays();

              $vulnerability_check->show_vulnerable_variables();
              $vulnerability_check->show_output_variables();

              //$vulnerability_check->show_parser_variables_with_dependencies();
              $vulnerability_check->show_parser_variables();
              //$vulnerability_check->show_parser_variables_lookup();

              $vulnerability_check->show_file_functions();
              $vulnerability_check->show_used_functions();
              $vulnerability_check->show_file_classes();
              $vulnerability_check->show_files_include_require();
             */
            // echo "<hr>";
            unset($vulnerability_check);
            $vulnerability_check = null;
            $i++;
        }
        
        echo "<tr><td></td><td>$total_num_vulnerabilities</td><td>" . sprintf('%01.5f', $total_time) . "</td></tr></table>";
        fclose($csv_file);
        //fclose($csv_file_add);
        fclose($csv_file_non);
        //fclose($csv_file_add_non);

        fflush($sql_file);
        fflush($sql_file2);

        $output_text = '<br />';
        $output_text = $output_text . "<hr><b>" . $total_num_vulnerabilities . " vulnerabilities found in " . $count_files . ' files in ' . sprintf('%01.2f', $total_time) . " seconds.</b><br />";
        $output_text = $output_text . '<hr><br />';
/*         $output_text = $output_text . "<br>Parser variables..........: $num_parser_variables";
        $output_text = $output_text . "<br>Vulnerable variables......: $num_vulnerabilities";
        $output_text = $output_text . "<br>Non-vulnerable variables..: $num_non_vulnerabilities"; */
        $output_text = $output_text . '</div>';

        echo $output_text;

        $output_text = "<tr><td></td>";
        $output_text .= "<td></td>";
        $output_text .= "<td></td>";
        $output_text .= "<td></td>";
        if ($num_vulnerabilities) {
            $output_text .= "<td style='color:red'>$total_num_vulnerabilities</td>";
        } else {
            $output_text .= "<td>$total_num_vulnerabilities</td>";
        }
        $output_text .= "<td>$total_num_vulnerabilities_XSS</td>";
        $output_text .= "<td>$total_num_vulnerabilities_SQLi</td>";
        $output_text .= "<td>" . sprintf('%11.3f', $total_time) . "</td>";
        $output_text .= "<td></td>";
        $output_text .= "<td>$count_files</td>";
        $output_text .= "<td>num_lines_of_code</td></tr>";
        fprintf($output_file, "%s\n", $output_text) or die("Could not write to file");
        fprintf($output_file, "%s\n", "</table>") or die("Could not write to file");
        fflush($output_file);

        fprintf($output_file, "%s\n", $output_text) or die("Could not write to file");
        fclose($output_file);
        echo "<h1>File summary results</h1>";
        echo "<p><a href='$this->output_dir'>$this->output_dir</a></p>";
        echo "<p><a href='$href_html'>$href_html</a></p>";
        echo "<p><a href='$href_csv'>$href_csv</a></p>";
		echo "<p><a href='$href_sql2'>$href_sql2</a></p>";
        echo "<p><a href='$href_csv_non'>$href_csv_non</a></p>";
    }

}
?>
<br/><br/></body></html>