<?php

/**
 *
 * phpSAFEe - PHP Security Analysis For Everyone
 *
 * Copyright (C) 2013 by Jose Fonseca (jozefonseca@gmail.com)
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
 *
 * Date:
 * 2014-10-29
 * 2014-10-30, fix find_match
 * 2014-10-30, fix bind par to 1st var body. OK | trainted ...  NOK
 * 2014-10-31, trainted/vulnerability ...  NOK
 * 2014-11-01, trainted/vulnerability ...  NOK, 0#qtrans_checkSetting#QTRANSLATE_CONF,  0#qtrans_checkSetting#QTRANS_CHECKSETTING
 * 2014-11-02, trainted/vulnerability ...  NOK, 0#qtrans_checkSetting#QTRANSLATE_CONF,  0#qtrans_checkSetting#QTRANS_CHECKSETTING
 * 2014-11-03, trainted/vulnerability ...  NOK, fix 0#qtrans_checkSetting#QTRANSLATE_CONF,  0#qtrans_checkSetting#QTRANS_CHECKSETTING OK
 *              add function show_variables_csv($variables, $text, $csv_file_name)
 *
 * 2014-11-04  (059 - 00 / 01    0.289    /Users/pnunes/Desktop/Dropbox/_PhD/php_tests/Core/vulnerable plugins/occasions 1.0.4/occasions.php    1    699
 * 2014-11-05  added files_fucntions_lookup[] and used_function_lookup[]
 *
 *
 * 2015-01-29
 *
 * $this->files_functions[] - add _PHPI_METHOD_COMPLETE_NAME
 *
 * _PHPI_METHOD_COMPLETE_NAME - name of the class#name of the function_1#name of the function_2 (function in functions)
 *
 * 2015-02-04
 *
 * function parse_user_defined_function_method_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $called_function_name, $called_function_index) {
 *   TO
 * function parse_user_defined_function_method_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $called_function_name, $called_function_index) {
 */
require_once 'class-php-file.php';

class PHP_Parser
{

    protected $_PHPI_CONSTANT_NAMES;
    protected $count_find_match = 0;


    public function get_PHPI_CONSTANT_NAMES()
    {
        return $this->_PHPI_CONSTANT_NAMES;
    }

    /**
     * The parser debug2 html formated data
     * Append data progressively
     * @var boolean
     */
    protected $parser_debug2_flag = false;

    /**
     * The parser debug2 html formated data
     * Adds data at the end of the analysis.
     * @var boolean
     */
// write
    protected $parser_debug2_flag_file = false;

    /**
     * The parser debug counter
     * @var int
     */
    protected $parser_debug2_counter = 0;

    /**
     * Parser debug2 html text
     * @var string
     */
    protected $parser_debug2_text = "";

    /**
     * The parser debug counter
     * @var fstream
     */
    protected $parser_debug2_file_stream;
    protected $parser_debug2_file_path = './output/';

    /**
     * @var array
     */
    protected $function_count;

    /**
     * The object of the class Php_File
     * @var Php_File class object
     */
    public $files;

    /**
     * Multi-dimensional associative array with the PHP user defined functions
     * @var array
     */
    protected $files_functions;
    protected $files_functions_lookup;
    /*
   * array 1D [file_name + class(es)_name + function_name] -  integers (index of)
   */
    protected $used_functions_lookup; // PN 2014-10-19

    /**
     * Multi-dimensional associative array with the PHP user defined classes
     * @var array
     */
    protected $files_classes;
    /*
   * array 1D [file_name + class(es)_name + function_name] -  integers (index of)
   */


    /*
   * array 2-D [file_name][$i] - integers (index of)
   *
   * To use tabling
   */
    protected $start_of_php_line_lookup; // PN 2014-10-20

    /*
   * array 2-D [file_name][$i] - integers (index of)
   *
   * To use tabling
   */
    protected $end_of_php_line_lookup; // PN 2014-10-20

    /*
   * array 2-D [file_name][$i] - integers (index of)
   *
   * To use tabling
   */
//protected $find_match_T_FUNCTION;

    /*
   * array 3D
   * find_token_lookup[$file_name][$block_start_index][$token]
   *
   *
   */
    protected $find_token_lookup;

    /*
   *
   * array 2D
   * find_previous_containing_function_from_index_lookup[$file_name][$block_index]
   *
   */
    protected $find_previous_containing_function_from_index_lookup;

    /*
   *
   * array 2D
   * $get_function_method_name_lookup[$file_name][$file_index]
   *
   */
    protected $get_function_method_name_lookup;

    /*
   * array 2D
   *
   * get_variable_property_name_lookup[$file_name][$file_index]
   *
   */
    protected $get_variable_property_name_lookup;

    /*
   * array 2D
   *
   * get_variable_property_complete_array_name_lookup[$file_name][$file_index]
   *
   */
    protected $get_variable_property_complete_array_name_lookup;


    /*
   * array 2-D [file_name][$i] - integers (index of)
   *
   * To use tabling
   */
    protected $find_function_name_of_code_lookup;

    /**
     * Multi-dimensional associative array with the PHP user defined functions
     * @var
     */
    /*
   * array 2-D [file_name][$i] - integers (index of) ???
   *
   * To use tabling
   */
    protected $check_variable_function_property_method_lookup;
    protected $start_time = 0;   // PN
    protected $time_execution_of = 0;   // PN  to gauge for function in currently in tests
    protected $count_execution = 0;

    /**
     *
     * @var
     */
    protected $main_parser_level = -1;   // PN

    /**
     * Array
     * @var
     */
    protected $main_parser_levels;   // PN

    /**
     * Multi-dimensional associative array with all the functions used in the code
     * @var array
     */
    protected $used_functions;

    /**
     * Multi-dimensional array with the PHP user defined functions stack
     * This is used to test for recursive functions, so they are not parsed more than once at a time
     * @var array
     */
    protected $functions_stack;

    /**
     * The parser debug data
     * @var array
     */
    private $parser_debug;

    /**
     * Multi-dimensional array with the PHP includes and requires
     * @var array
     */
    protected $files_include_require;

    /**
     * Multi-dimensional associative array with the PHP variable attributes
     * @var array
     */
    protected $parser_variables;
//protected $parser_variables_user_functions;
    protected $parser_variables_user_functions_lookup;

    /**
     * 2-dimensional associative, index array with the PHP variable attributes
     * [$file_name$variable_name$function_name][index]
     * @var array
     */
    protected $parser_variables_lookup;

    /**
     * ....
     * @var file stream
     */
    protected $text_file_stream;   //PN   see $file_debug = 1;   //PN
    protected $file_debug = 0;   //PN
    protected $echo_debug = 0;   //PN

    /**
     * echo parser variables
     * @var boolean
     */
    /*
   * array
   */

    protected $html_table_visible = 1;
    protected $echo_resume_report = 1;
    protected $echo_output_variables = 1;
    protected $echo_parser_variables = 1;
    protected $echo_parser_variables_with_dependencies = 0;
    protected $echo_parser_variables_lookup = 0;
    protected $echo_file_functions = 1;
    protected $echo_used_functions = 1;
    protected $echo_files_include_require = 1;

    protected $echo_vulnerable_variables = 1;
    protected $echo_vulnerable_variables_with_dependencies = 1;

    protected $echo_non_vulnerable_variables = 1;
    protected $echo_non_vulnerable_variables_with_dependencies = 1;

    protected $echo_vulnerable_variables_tree = 0; // not implemented
    protected $echo_tokens_array_of_arrays = 1;
    protected $echo_file_classes = 1;
    protected $file_write_resume_report = 0;
    protected $file_write_output_variables = 1;
    protected $file_write_parser_variables = 0;
    protected $file_write_vulnerable_variables = 1;
    protected $file_write_non_vulnerable_variables = 1;

    protected $csv_write_parser_variables = 0;
    protected $file_write_parser_variables_lookup = 0;
    protected $file_write_parser_variables_with_dependencies = 0;
    protected $file_write_file_functions = 0;
    protected $file_write_used_functions = 0;
    protected $file_write_files_include_require = 0;
    protected $file_write_tokens_array_of_arrays = 1;
    protected $file_write_echo_vulnerable_variables = 0;
    protected $file_write_vulnerable_variables_with_dependencies = 0;
    protected $file_write_vulnerable_variables_tree = 0;  // not implemented
    protected $file_write_file_classes = 0;
    protected $output_check_array = null;

    public function get_output_check_array()
    {
        return $this->output_check_array;
    }

    public function set_output_checkboxes($chk, $value)
    {
//echo "<p> SET: $chk, $value</p>";
        if (isset($this->$chk))
            if (isset($value))
                if (is_int($value))
                    $this->$chk = $value;
                else
                    $this->$chk = 0;
//echo "<p>$chk " . $this->$chk . "</p>";
    }

    public function get_output_checkboxes($chk)
    {
//echo "<p>$chk ". $this->$chk . " </p>";
        if (isset($this->$chk))
            return $this->$chk;
        return 0;
    }

    /**
     * .... with the PHP variable attributes
     * @var string
     */
    protected $threshold_time_php_tag = 1;    // PN

    function echo_h1($text, $color)
    {
        echo "<h1 style='color:$color;'>$text</h1>";
    }

    function generate_code_from_tokens($tokens, $start_index, $end_index)
    {
        $code = "";

        for ($i = $start_index; $i <= $end_index; $i++) {
            $token = $tokens[$i];
            if (is_array($token)) {
                $type = token_name($token[0]);
                $value = $token[1];
                $value = htmlspecialchars($value);
                $line = $token[2];
                $code .= "$value ";
            } else {
                $code .= $token;
            }
        }
        return $code;
    }

// parse function including parametres dependencies

    /**
     * adds item to then $parser_variables_lookup two-dimensional associative array
     *
     * @param type $key string union of the $file_name, $variable_name and $function_name
     * @param type $index integer index of the $parser_variables that is being inserted
     */
    function add_parser_variables_lookup($file_name, $variable_name, $function_name, $index)
    {
// if the does not exists insert it with the index 0 else insert with the last index + 1
// hash table with collisions stored in the 2nd dimension
        $function_name = strtoupper($function_name);
        $key = "$file_name#$variable_name#$function_name";
        $this->parser_variables_lookup["$key"][] = $index;
    }

    /**
     *
     * @param type $file_name
     * @param type $variable_name
     * @param type $function_name
     * @param type $index
     * @return null
     */
    function delete_variable_index_with_lookup($file_name, $variable_name, $function_name, $index)
    {
// echo "<p style='color:brown'>function delete_variable_index_with_lookup($file_name, $variable_name, $function_name, $index)<p>";
        $function_name = strtoupper($function_name);
        $key = "$file_name#$variable_name#$function_name";

        if (isset($this->parser_variables_lookup["$key"])) {
            $c = count($this->parser_variables_lookup["$key"]);
            for ($i = 0; $i < $c; $i++) {
                if (isset($this->parser_variables_lookup["$key"][$i])) {
                    if ($index === $this->parser_variables_lookup["$key"][$i]) {
// if only one, delete all item $key, else delete the item [$key][$i]
                        if ($c === 1) {
                            unset($this->parser_variables_lookup["$key"]);
//$this->echo_h1("DELETE $key $index c($c) = 1", "red");
// $c2 = 0;
                        } else {
//$this->echo_h1("DELETE $key $index c($c) > 1", "blue");
                            unset($this->parser_variables_lookup["$key"][$i]);
// normalize, delete unsset items
//$this->parser_variables_lookup["$key"] = array_values($this->parser_variables_lookup["$key"]);
//$c2 = count($this->parser_variables_lookup["$key"]);
                        }
// echo "<hr /><h2 style='color:brown'>$key - count: $c/$c2, index: $index </h2>";
                        return;
                    }
                }
            }
        }
    }

    /**
     *
     * @return array (lines of code of first file, total lines of code of included files)
     */
    function get_number_lines_of_code()
    {
        $f_tokens = $this->files->files_tokens;
        $num_lines_of_code = 0;
        if (isset($f_tokens)) {
            $lines_of_code_main = 0;
            foreach ($f_tokens as $file_name => $dummy) {
                $last_line = 0;
                $j = count($f_tokens[$file_name]) - 1;
                while (($j >= 0) && (!is_array($f_tokens[$file_name][$j]))) {
                    $j--;
                }
                $last_line = $f_tokens[$file_name][$j][2];
                if ($file_name === 0) {
                    $lines_of_code_main = $last_line;
                }
                $num_lines_of_code = $num_lines_of_code + $last_line;
            }
            return array($lines_of_code_main, $num_lines_of_code - $lines_of_code_main);
        }
        return array(0, 0);
    }

    /**
     *
     * @return int
     */
    function get_number_lines_of_code_oop()
    {
        $num_lines_of_code = 0;
        if (isset($this->files_classes)) {
            foreach ($this->files_classes as $data) {
                $num_lines_of_code = $num_lines_of_code + $data[_PHPI_END_LINE] - $data[_PHPI_START_LINE] + 1;
            }
        }
        return $num_lines_of_code;
    }

    /**
     *
     * @return int
     */
    function get_number_of_used_user_defined_function()
    {
        $num = 0;
        if (isset($this->used_functions)) {
            foreach ($this->used_functions as $data) {
                if ('user defined' === $data[_PHPI_USER_DEFINED])
                    $num++;
            }
        }
        return $num;
    }

    /**
     *
     */
    function set_resume_report()
    {
        $loc = $this->get_number_lines_of_code();
        $per0 = sprintf("%.2f", round($loc[0] / ($loc[0] + $loc[1]) * 100.0, 2));
        $per1 = sprintf("%.2f", round($loc[1] / ($loc[0] + $loc[1]) * 100.0, 2));
        $this->resume_report[] = array("Lines of code of main entry", $loc[0], $per0);
        $this->resume_report[] = array("Total lines of code", $loc[0] + $loc[1], '100.00');
        $this->resume_report[] = array("Total lines of included code", $loc[1], $per1);
        $this->resume_report[] = array("Included files", isset($this->files->files_tokens) ? count($this->files->files_tokens) - 1 : 0, '');
        $loc_oop = $this->get_number_lines_of_code_oop();
        $per_oop = sprintf("%.2f", round($loc_oop / ($loc[0] + $loc[1]) * 100.0, 2));
        $this->resume_report[] = array("Lines of code OOP", $loc_oop, $per_oop);
        $this->resume_report[] = array("User defined functions", isset($this->files_functions) ? count($this->files_functions) : 0, '');
        $n = $this->get_number_of_used_user_defined_function();
        $this->resume_report[] = array("Used user defined functions", $n, '');
        $this->resume_report[] = array("Used functions", isset($this->used_functions) ? count($this->used_functions) : 0, '');
        $this->resume_report[] = array("Classes", isset($this->files_classes) ? count($this->files_classes) : 0, '');
        $nv = count($this->get_vulnerable_variables());
        $this->resume_report[] = array("Vulnerable variables", $nv, '');
        $nv = count($this->output_variables);
        $this->resume_report[] = array("Output variables", $nv, '');
        $nv = count($this->parser_variables);
        $this->resume_report[] = array("Parser variables", $nv, '');
    }

    /**
     *
     * @return type
     */
    function show_resume_report($html_file_name)
    {
        if (($this->echo_resume_report === 0) && ($this->file_write_resume_report === 0))
            return;
        $this->set_resume_report();
        $html = "<h1>Resume report </h1>";
        $html .= "<table>";
        $html .= "<tr><th>Description</th><th>Value</th><th>%</th></tr>";
        foreach ($this->resume_report as $line) {
            $html .= '<tr>';
            $html .= '<td>' . $line[0] . '</td>';
            $html .= '<td style="text-align:right;">' . $line[1] . '</td>';
            $html .= '<td style="text-align:right;">' . $line[2] . '</td>';
            $html .= '</tr>';
        }
        $html .= "</table>";
        if ($this->echo_resume_report === 1)
            echo $html;
        //if ($this->file_write_resume_report === 0)

        $fs = fopen($html_file_name, "wt");
        if ($fs != null) {

            fprintf($fs, "%s", $html);
            fclose($fs);
            echo "<p><a href='$html_file_name'>$html_file_name</a></p>" . "\n";
        } else {
            echo "<p>Can't write to file $html_file_name</p>";
        }

    }

    function show_parser_variables()
    {
        $this->show_variables($this->parser_variables, 'Parser Variables', $this->echo_parser_variables, "ParserVariables.html", $this->file_write_parser_variables);
        if ($this->csv_write_parser_variables)
            $this->show_variables_csv($this->parser_variables, 'CSV - Parser Variables', "ParserVariables.csv");
    }


    function show_file_classes()
    {
        $this->show_variables($this->files_classes, 'File Classes', $this->echo_file_classes, "FileClasses.html", $this->file_write_file_classes);
    }


    function show_files_include_require()
    {
        $this->show_variables($this->files_include_require, 'Files Include Require', $this->echo_files_include_require, "FilesIncludeRequire.html", $this->file_write_files_include_require);
    }

// function
// PN

    function execution_time($time_start, $text)
    {
        $time_end = microtime(true);
        $time = $time_end - $time_start;
        $s = sprintf('%01.2f', $time);
        echo "<p>Time <b>$text</b>: $s</p>";
    }

// PN
    function array_data_token_html_td($token, $cor)
    {

        if (is_array($token)) {
//$token_name = is_array($token) ? $token[0] : null;
//$token_data = is_array($token) ? $token[1] : $token;
            $type = token_name($token[0]);
            $value = $token[1];
            $value = htmlspecialchars($value);
            $line = $token[2];
            $s = "<td>$type</td><td>$line</td><th style='color:$cor'><quote>$value<quote></th>";
        } else {
            $type = $token;
            $s = "<td></td><td></td><td style='color:$cor'>$type</td>";
        }
        return ($s);
    }

    function show_tokens_array_of_arrays()
    {
        if (count($this->files->files_tokens_names)) {
            $file_name = $this->files->files_tokens_names[0];
            if (($this->echo_tokens_array_of_arrays) || ($this->file_write_tokens_array_of_arrays)) {
                $dir = '/output/';
                $this->write_tokens_array_of_arrays($dir, $this->files->files_tokens);
            }
        }
    }

    function write_tokens_array_of_arrays($dir, $files_files_tokens, $orientation = 'P')
    {
        //PN - print tokens in a HTML table
        if ($this->echo_tokens_array_of_arrays)
            echo "<h1>Files tokens</h1>";

        $base_path = dirname(__FILE__); // dirname($this->files->files_tokens_names[0]);
        foreach ($files_files_tokens as $key => $token) {
            $file = $this->files->files_tokens_names[$key];
            $html_file_name = $base_path . $dir . basename($file) . "_tokens.html";
            $f = fopen($html_file_name, "wt");
            if ($f === null) {
                echo "<p>Can't write to file $html_file_name</p>";
                die();
            }

            $s = "<style> table, td, th {text-align:center; padding:2px; border: 1px solid black;border-collapse: collapse;}</style>";
            $jQuery = "<script src='" . BASE_URL . "jquery.js'/>";
            $jQuery .= <<<_END
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
            fprintf($f, "%s", $jQuery);
            fprintf($f, "%s", $s);

            $html_file_name = realpath(dirname($html_file_name)) . DIRECTORY_SEPARATOR . basename($html_file_name);
            $html_file_name_link = './' . $dir . basename($html_file_name);

            $variable_name = "";
            $line_mark = $line_end = 0;
            $variable_name = str_replace(array('$', "'", '"'), array('%24', '%27', '%22'), $variable_name);
            
            $file = "<h2><a href='" . BASE_URL . "show_php_file.php?file=$file&variable_name=$variable_name&line_mark=$line_mark&line_end=$line_end'>$file</a></h2>";

            if ($this->echo_tokens_array_of_arrays)
                echo "<p><a href='$html_file_name_link'>$html_file_name</a></p>";

            $tokens = $files_files_tokens[$key];
            $s = "$file<table><tr><th>#</th><th>name</th><th>value</th><th>line</tr>" . "\n";
            fprintf($f, "%s", $s);
            for ($k = 0; $k < count($tokens); $k++) {
                if (is_array($token[$k])) {
                    $name = token_name($token[$k][0]);
                    $value = $token[$k][1];
                    $value = htmlspecialchars($value);
                    $line = $token[$k][2];

                    $s = "<tr>   <td style='text-align:right'>$k</td>  <td>$name</td>   <td>$value</td>    <td>$line</td></tr>" . "\n";
                    fprintf($f, "%s", $s);
                } else {
                    $value = $token[$k];
                    $s = "<tr>   <td style='text-align:right;'>$k</td>  <td></td>  <td style='color:blue;'>$value</td>   <td></td></tr>" . "\n";
                    fprintf($f, "%s", $s);
                }
            }
            $s = "</table>" . "\n";
            fprintf($f, $s);
            fclose($f);
        }
    }

    /**
     * @param string $file_name
     * @param type $line
     * @param type $lines
     * @return string
     */
    function get_lines_of_code($file_name, $variable_name, $line, $lines, $cor)
    {
//$end_index = end_of_php_line($file_name, $end_index);
        $file_name = realpath(dirname($file_name)) . DIRECTORY_SEPARATOR . basename($file_name);
        $text_lines = "<table>";
        $text_lines_raw = '';
				$line;
        if ((file_exists($file_name)) && (is_file($file_name))) {
            $file_contents = file_get_contents($file_name);
            $convert = preg_split('/\r\n|\r|\n/', $file_contents);
//$convert = explode("\n", $file_contents); //create array separate by new line
            if ($lines >= 0) {
                $a = (($line - $lines) >= 0) ? $line - $lines : 0;
                $b = (($line + $lines) < count($convert)) ? $line + $lines : count($convert) - 1;
            } else {
                $lines = -$lines;
                $a = ($line - $lines >= 0) ? $line - $lines : 0;
                $b = $line;
            }
            $variable_name0 = $variable_name;
            $variable_name = str_replace(array('$', "'", '"'), array('%24', '%27', '%22'), $variable_name);
             
            $text_lines .= "<tr><th>File</th><td><a href='" . BASE_URL . "show_php_file.php?file=$file_name&line_mark=$a&line_end=$b&variable_name=$variable_name#target_mark'>$file_name</a></td></tr>";

            $text_lines .= "<tr><th>Line</th><td>$line</td></tr>";
            for ($i = $a; $i <= $b; $i++) {
				$ii = $i-1;
				if ($ii < 0) continue;
                $text_lines_raw .= "$i ## " . $convert[$ii];
                $text_line = htmlentities($convert[$ii]); //write value by index

//if ($i == $line)

                $text_line = str_replace($variable_name0, "<span style='color:$cor;'>$variable_name0</span>", $text_line);
//echo "<p>$variable_name <br>$text_line</p>";
                $text_lines .= "<tr><td>" . ($i) . "</td><td>$text_line</td></tr>";
            }
        } else {
            $text_lines .= "<tr><td>Cannot read the file.</td></tr>";
        }
        $text_lines .= "</table>";
        return array($text_lines, $text_lines_raw);
    }

    /**
     *
     * @param type $variables
     * @param type $index
     * @param type $i
     * @return string
     */
    function show_variable_dependencies($variables, $index, $i)
    {
        if (!isset($variables[$index]))
            return '';

        $variable = $variables[$index];
        $name = $variable[_PHPI_NAME];
        $line = $variable[_PHPI_LINE];
        $destroy = $variable[_PHPI_EXIST_DESTROYED];
        $tainted = $variable[_PHPI_TAINTED];
        $cor = ($tainted === 'tainted') ? 'red' : 'green' . "; background-color: lightpink;";
        $vulnerability = $variable[_PHPI_VULNERABILITY];
        $parser_file_base_name = basename($this->files->files_tokens_names[0]);
        $file_name = $this->files->files_tokens_names [$variable[_PHPI_FILE]];
        $lines_of_code = $this->get_lines_of_code($file_name, $name, $line, 2, $cor)[0];
        $file_name = basename($this->files->files_tokens_names [$variable[_PHPI_FILE]]);
        $file_name_title = $file_name . " (Entry file: $parser_file_base_name)";
        $base_dir = $this->files->files_tokens_names [$variable[_PHPI_FILE]];  //dirname($this->files->files_tokens_names[0]);
        if ($tainted == _PHPI_TAINTED) {
            $color = " style='color:red;'";
            $tainted = "<td $color>$tainted</td>";
        } else {
            $color = "";
            $tainted = "<td $color>$tainted</td>";
        }
        if ($destroy == 'destroyed') {
            $color1 = " style='color:blue;' ";
        } else {
            $color1 = "";
        }
        $di = $variable[_PHPI_DEPENDENCIES_INDEX];
        if (is_array($di))
            $dep_title = "<th>Dependencies</th>";
        else
            $dep_title = "";
//$html = "<table><tr><th>index</th><th>name</th><th>line</th><th $color1>destroy</th><th>dependencies</th></tr><tr><td>$index</td><td $color>$name</td><td>$line</td><td>$destroy</td>";
        $html = "<table><tr><th>#index</th><th>Code</th><th>Entry File</th><th>Tainted</th>$dep_title</tr>";
        $html .= "<tr><td $color>$index</td><td title='$file_name_title'>$lines_of_code </td><td title='$base_dir'>$file_name</td>$tainted";
//$html = "<table><tr><th>name</th><th>line</th><th $color1>destroy</th><th>dependencies</th></tr><tr><td $color>$name</td><td>$line</td><td>$destroy</td>";
        if (is_array($di)) {
            foreach ($di as $index => $index_variable) {
                $html2 = $this->show_variable_dependencies($variables, $index_variable, $i);
                if ($html2 != "") {
                    $html .= "<td>$html2</td>";
                }
            }
        }
        $html .= "</table>" . "\n";
        return $html;
    }

    /**
     *
     * @param type $vulnerable
     * @param type $variables
     * @param type $text
     * @param type $echo_html
     * @param type $html_file_name
     * @param type $write_in_file
     * @return type
     */
    function show_vulnerable_variables_with_dependencies_($parsed_file_ini, $vulnerable, $variables, $text, $echo_html, $html_file_name, $write_in_file)
    {
        if (($echo_html === 0) && ($write_in_file === 0)) {
            return;
        }
        if (!isset($variables)) {
            return;
        }
        $count = count($variables);
        $id = str_replace(" ", "", $html_file_name);
        $id = str_replace(".", "", $id);
        $c = count($variables);
        $script = "var o = document.getElementById('" . $id . "'); if (o.style.display == 'block') {o.style.display = 'none'; document.getElementById(this.id).innerHTML = 'Show';} else { o.style.display = 'block';document.getElementById(this.id).innerHTML = 'Hide';}" . PHP_EOL;
        $tr_even_odd = "tr:nth-child(even) {background: #eee} tr:nth-child(odd) {background: #FFF}" . "\n";
        $html = "<style>$tr_even_odd table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>" . "\n";
        $html .= "<h1 style='color:black;'>$text</h1>";
        $display = 'none';
        if ($this->html_table_visible)
            $display = 'block';
        if ($count > 0) {
            $html2 = "";
            $number = 0;
            for ($i = 0; $i < $count; $i++) {
                if (($vulnerable == false) || ((UNKNOWN != $variables[$i][_PHPI_VULNERABILITY]) && (FILTERED != $variables[$i][_PHPI_VULNERABILITY]))) {
                    // if ( 'SQL Injection' == $variables[$i][_PHPI_VULNERABILITY] ) {
                    $number++;
                    $name = $variables[$i][_PHPI_NAME];
                    $vulnerability = $variables[$i][_PHPI_VULNERABILITY];
                    $tainted = $variables[$i][_PHPI_TAINTED];
                    $html2 .= "<h2> $number . Name: <span style='color:maroon;'>$name</span>  - Vulnerability: $vulnerability</h2>";
                    $deps = $this->show_variable_dependencies($variables, $i, $number);
                    $html2 .= $deps . "\n";
                }
            }
        } // count
        $html3 = "<div id='$id' style='display:$display;border:none;'>" . "\n";
        $html1 = "<p><span id='S_$id' onclick=" . '"' . $script . '"' . "style='border:1px solid black;padding:3px;background-color:#eee;'>Show</span> Count: $number</p>" . "\n";
        $html = $html . $html1 . $html3 . $html2 . '</div>';
        if ($echo_html) {
            echo $html;
        }
        $s = $html_file_name;
        if ($write_in_file) {
            $fs = fopen($s, "wt");
            if ($fs != null) {
                fprintf($fs, "%s", $html);
                fclose($fs);
            } else {
                echo "<p>Can't write to file $s</p>";
            }
        }
        return $s;
    }


    /**
     *
     * @param type $html_file_name
     * @param type $echo_html
     * @param type $write_in_file
     */
    function show_parser_variables_lookup()
    {
        return $this->show_parser_variables_lookup_("Parser variables lookup", $this->echo_parser_variables_lookup, "ParserVariablesLookup.html", $this->file_write_parser_variables_lookup);
    }

    /**
     *
     * @param type $text
     * @param type $echo_html
     * @param type $html_file_name
     * @param type $write_in_file
     * @return type
     */
    function show_parser_variables_lookup_($text, $echo_html, $html_file_name, $write_in_file)
    {
        $id = str_replace(" ", "", $html_file_name);
        $id = str_replace(".", "", $html_file_name);
        $c = count($this->parser_variables_lookup);
        $script = "var o = document.getElementById('" . $id . "'); if (o.style.display == 'block') {o.style.display = 'none'; document.getElementById(this.id).innerHTML = 'Show';} else { o.style.display = 'block';document.getElementById(this.id).innerHTML = 'Hide';}" . PHP_EOL;
        $tr_even_odd = "tr:nth-child(even) {background: #eee} tr:nth-child(odd) {background: #FFF}" . "\n";
        $html = "<style>$tr_even_odd table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>" . "\n";
        $html .= "<h1 style='color:black;'>$text</h1>" . "\n";
        $html .= "<p><span id='S_$id' onclick=" . '"' . $script . '"' . "style='border:1px solid black;padding:3px;background-color:#eee;'>Show</span> Count: $c</p>" . "\n";

        $html .= $this->show_parser_variables_lookup_2($id);
        if ($echo_html) {
            echo $html;
        }
        if ($write_in_file) {
// the PHP parser file
            $parser_file_base_name = basename($this->files->files_tokens_names[0]);
            $s = './output/' . $parser_file_base_name . '_' . $html_file_name;
            $fs = fopen($s, "wt");
            if ($fs != null) {
                fprintf($fs, $html);
                fclose($fs);
                echo "<p><a href='$s'>$text</a></p>" . "\n";
            } else {
                echo "<p>Can't write to file $s</p>";
            }
        }
        return $html;
    }

    function show_parser_variables_lookup_2($id)
    {
        if (!isset($this->parser_variables_lookup))
            return null;

        $display = 'none';
        if ($this->html_table_visible)
            $display = 'block';
        $html = "<table id='$id' style='display:$display;border:none;'>";

        $c0 = 0;
        $c = 0;
        $html .= "<tr><th>#</th><th>key 1</th><th>indexes</th></tr>";

        foreach ($this->parser_variables_lookup as $k => $v_array) {
            $c2 = count($v_array);
            $html .= "<tr><td>$c0</td><td style='vertical-align:top;'>$k <br/> ($c2)</td><td>";
            $html .= "<table>" . "\n";
            $html .= "<tr><th>#</th><th>key</th><th>index</th><th>exist_destroyed</th><th>line</th></tr>" . "\n";
            $c0++;
            foreach ($v_array as $k2 => $index) {
                $ed = $this->parser_variables[$index][_PHPI_EXIST_DESTROYED];
                $line = $this->parser_variables[$index][_PHPI_LINE];
                $dep = "";
                $dependencies_index = $this->parser_variables[$index][_PHPI_DEPENDENCIES_INDEX];
                if (isset($dependencies_index)) {
                    $dep = "<table><tr>";
                    foreach ($dependencies_index as $dep_index) {
                        $dep .= "<td>$dep_index<td>";
                    }
                    $dep .= "</tr></table>";
                }
                $html .= "<tr><td>$c</td><td>$k2</td><td>$index</td><td>$ed</td><td>$line</td><td>$dep</td></tr>" . "\n";
                $c++;
            }
            $html .= "</table>" . "\n";
            $html .= "</td></tr>" . "\n";
        }
        $html .= '</table>' . "\n";

        return $html;
    }

    function show_variables_csv($variables, $text, $csv_file_name)
    {
        if (!isset($variables))
            return;
        $id = str_replace(" ", "", $csv_file_name);
        $id = str_replace(".", "", $csv_file_name);
        $count = count($variables);
        if ($count > 0) {
            $variable = $variables[0];
            $csv = '#';
            foreach ($variable as $key => $value) {
                $csv .= ";$key";
//$csv .= ";" ." _PHPI_CONSTANT_NAMES[$key]";
            }
            $csv .= "\n";
            for ($i = 0; $i < $count; $i++) {
                $variable = $variables[$i];
                $csv .= "$i";
                foreach ($variable as $value) {
                    if (is_array($value)) {
                        foreach ($value as $data) {
                            if (is_array($data)) {
                                foreach ($data as $p) {
                                    $csv .= ";$p";
                                }
                            } else {
                                $csv .= ";$data";
                            }
                        }
                    } else {
                        $csv .= ";$value";
                    }
                }
                $csv .= "\n";
            }
        } // count

        $parser_file_base_name = basename($this->files->files_tokens_names[0]);
        $s = './output/' . $parser_file_base_name . '_' . $csv_file_name;
        $csv = $s . '-' . $text . "\n" . $csv;
        $fs = fopen($s, "wt");
        if ($fs != null) {
            fprintf($fs, $csv);
            fclose($fs);
            echo "<p><a href='$s'>$text</a></p>" . "\n";
        } else {
            echo "<p>Can't write to file $s</p>";
        }
    }


    function show_file_functions_SS($parsed_file_ini, $files_functions, $text, $echo_html, $html_file_name, $write_in_file)
    {
        if (!isset($files_functions))
            return;

        $html = <<<_END
      <script src="jquery.js"></script>
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

        /*	_PHPI_NAME => 'function',
            _PHPI_FILE => $file_name,
            _PHPI_CLASS => $class_name,
            _PHPI_EXECUTED => 'executed',
            _PHPI_START_LINE => 1, // old: 0
            _PHPI_END_LINE => $file_end_function_line,
            _PHPI_START_INDEX => 0,
            _PHPI_END_INDEX => $count - 1,
            _PHPI_PARAMETERS => null,
            _PHPI_CALLED_FUNCTIONS => $called_functions,
            _PHPI_START_PARAMETER_INDEX => -1, // new PN
            _PHPI_END_PARAMETER_INDEX => -1, // new PN
            _PHPI_METHOD_COMPLETE_NAME => $key      // new OOP


                         _PHPI_FILE => $called_file_name,
                    _PHPI_CLASS => $called_class_name, // TODO: object of classe X - determinate context.
                    _PHPI_NAME => $called_function_name,
                    _PHPI_START_LINE => $tokens[$i][2],
										erro: It was _PHPI_LINE, lines, 
												2161 ( _PHPI_START_LINE => $tokens[$i][2],), of class-php-parser.php 
												2291:  _PHPI_LINE => $tokens[$j][2],
												fixed to: _PHPI_LINE
                    _PHPI_START_INDEX => $start_index,
                    _PHPI_METHOD_COMPLETE_NAME => $called_function_name, // OOP - object creat
										new on 2016-11-30
										_PHPI_PARAMETERS => function_parameters [] 


                         $function_parameters[] = array(
                            _PHPI_PARAMETER_NAME => $tokens[$j][1],
                            _PHPI_LINE => $tokens[$j][2],
                        );
                        */

				$fs = fopen($html_file_name, "wt");
				fprintf($fs, "%s\n", "PHP_PLUGIN;PHPI_FILE_BASE;PHPI_SENSITIVE_SINK;PHPI_LINE;PHPI_SENSITIVE_SINK_VULNERABILITY;executed_function_that_calls_the_function;parameters;function_that_calls_the_function;PHPI_START_LINE;lines_of_code;url_link") or die("Could not write to file");
						
        for ($i = 0, $count = count($files_functions); $i < $count; $i++) {
					//if ('executed' === $files_functions[$i][_PHPI_EXECUTED]) {
					if (1===1) {
						$executed = $files_functions[$i][_PHPI_EXECUTED];
            $function_that_calls_function = $files_functions[$i][_PHPI_NAME];
            $file_name = $files_functions[$i][_PHPI_FILE];
            $file_name = $this->files->files_tokens_names[$file_name];
            $file_name = str_replace("\\", '/', $file_name);
						$file_name_full =  $file_name;
						

            $initial_parsed_file_length_cut = strlen('H:\\_WORKLOADS_ORIGINAL\\ja111') + 1;
            $file_name = substr($file_name, $initial_parsed_file_length_cut);
            $plugin_name = explode('/', $file_name)[0];
            $file_name = substr($file_name, strpos($file_name, '/') + 1, strlen($file_name));

            $pars = $files_functions[$i][_PHPI_PARAMETERS];
            $parameters = '';
            if (is_array($pars)) {
                foreach ($pars as $par) {
                    if (is_array($par)) {
                        $parameters .= $par[_PHPI_PARAMETER_NAME] . ': ' . $par[_PHPI_LINE];
                    } else {
                        $parameters .= $par;
                    }
                }
            }
						$_start_line_of_the_function_that_calls = $files_functions[$i][_PHPI_START_LINE];

            //echo "<p>$function_that_calls_function ($parameters)</p>";
			if (is_array($files_functions[$i][_PHPI_CALLED_FUNCTIONS])) { //fix
				$count_files_functions_PHPI_CALLED_FUNCTIONS = count($files_functions[$i][_PHPI_CALLED_FUNCTIONS]);
			} else {
				$count_files_functions_PHPI_CALLED_FUNCTIONS = 0;
			}
            for ($j = 0, $jcount = $count_files_functions_PHPI_CALLED_FUNCTIONS; $j < $jcount; $j++) {
								$called_fun = $files_functions[$i][_PHPI_CALLED_FUNCTIONS][$j];
               /* foreach ($called_fun as $k => $v) {
                    echo "<p>$k ----------- $v</p>";
                }*/
                $called_function_name = $called_fun[_PHPI_NAME];
                $called_class_name = $called_fun[_PHPI_CLASS];
                $called_file_name = $called_fun[_PHPI_FILE];
								$pars = $called_fun[_PHPI_PARAMETERS];

								$parameters = '';
								if ($pars != null) {
									if (is_array($pars)) {
											foreach ($pars as $par) {
													if (is_array($par)) {
															if ($parameters == '')
																$parameters = $par[_PHPI_PARAMETER_NAME];
															else
																 $parameters .= ', ' . $par[_PHPI_PARAMETER_NAME];
													} else {
															$parameters .= $par;
													}
											}
									}
								}
                
                $line = $line_mark =  $line_end =  $called_fun[_PHPI_LINE];
								$vuln = $this->getFunctionVulnType($called_function_name);
								$lines_of_code = $this->get_lines_of_code($file_name_full, $called_function_name, $line, 0, 'red');
								
								//echo $lines_of_code[0];
								
								$lines_of_code = $lines_of_code[1];
								$lines_of_code = str_replace("##", '', $lines_of_code);
								$lines_of_code = str_replace(";", '##', $lines_of_code);
								$variable_name = $called_function_name;
								
								 
								$url_link = BASE_URL . "show_php_file.php?file=$file_name_full&line_mark=$line_mark&line_end=$line_end&variable_name=" . $variable_name . "&text=$text#target_mark";;
																 
								
								$csv = "$plugin_name;$file_name;$called_function_name;$line;$vuln;$executed;$parameters;$function_that_calls_function ($parameters);$_start_line_of_the_function_that_calls;$lines_of_code;$url_link";
               // echo "<p>$csv</p>";
							 fprintf($fs, "%s\n", $csv) or die("Could not write to file");
								fflush($fs);
            }
					}
        }
				fclose($fs);

        return;


        $id = str_replace(" ", "", $html_file_name);
        $id = str_replace(".", "", $html_file_name);
        $c = count($variables);
        $script = "var o = document.getElementById('" . $id . "'); if (o.style.display == 'block') {o.style.display = 'none'; document.getElementById(this.id).innerHTML = 'Show';} else { o.style.display = 'block';document.getElementById(this.id).innerHTML = 'Hide';}";
        $tr_even_odd = "tr:nth-child(even) {background: #eee} tr:nth-child(odd) {background: #FFF}";
        $html .= "<style>$tr_even_odd table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>";
        $html .= "<h1 style='color:black;'>$text</h1>";
        $html .= "<p><span id='S_$id' onclick=" . '"' . $script . '"' . "style='border:1px solid black;padding:3px;background-color:#eee;'>Show</span> Count: $c</p>";
        $display = 'none';
        if (($this->html_table_visible) && (!($variables === $this->parser_variables)))
            $display = 'block';
        $html .= "<table id='$id' style='display:$display;border:none;'>";

        $count = count($variables);
        if ($count > 0) {
            $variable = $variables[0];
            $html .= '<tr><th>#</th>';
            foreach ($variable as $key => $value) {
                $html .= '<th>' . strtolower(substr($this->_PHPI_CONSTANT_NAMES[$key], 6)) . '</th>';
//echo "$key => $value $html<br>";
            }
            $html .= '</tr><tr>' . "\n";
            for ($i = 0; $i < $count; $i++) {
//for ($i = 967; $i < $count-200; $i++) {
                $variable = $variables[$i];

                foreach ($variable as $key => $value) {
                    $html .= '<tr>';
                    $html .= '<td>' . ($i + 0) . '</td>';
                    if (is_array($value)) {
                        $html .= "<td><table><tr>";
                        foreach ($value as $data) {
                            if (is_array($data)) {
// parameters
                                //$html .= "<td><table><tr>";
                                foreach ($data as $p) {
                                    $html .= "<td>$p</td>";
                                }
                                //$html .= "</tr></table></td>";
                            } else {
                                $html .= "<td>$data</td>";
                            }
                        }
                        //$html .= "</tr></table></td>";
                        $html .= "</tr>";
                    } else {
                        if ($value === 'tainted')
                            $style = "style='color:red;'";
                        else if ($value === 'executed')
                            $style = "style='color:red;'";
                        else if ($value === 'user defined')
                            $style = "style='color:red;'";
                        else
                            $style = "";

// file name
//echo "$key $value<br>";
// echo $this->_PHPI_CONSTANT_NAMES[$key] . ' '. $value . '<br>';
                        if (strtolower(substr($this->_PHPI_CONSTANT_NAMES[$key], 6)) === 'file') {
                            $file_name = $this->files->files_tokens_names[$value];
                            $value = basename($this->files->files_tokens_names[$value]);
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
														 
                            $value = "<a href='" . BASE_URL . "show_php_file.php?file=$file_name&line_mark=$line_mark&line_end=$line_end&variable_name=" . $variable_name . "&text=$text#target_mark'>$value</a>";
                        }
                        $html .= "<td $style>$value</td>";
                    }
                    $html .= '<tr>' . "\n";
                }
            }
            $html .= '</table>' . "\n";
        } // count
        if ($echo_html) {
            echo $html;
        }
        if ($write_in_file) {
// the PHP parser file
            $parser_file_base_name = basename($this->files->files_tokens_names[0]);
            $s = './output/' . $parser_file_base_name . '_' . $html_file_name;
            $fs = fopen($s, "wt");
            if ($fs != null) {
                fprintf($fs, $html);
                fclose($fs);
                echo "<p><a href='$s'>$text</a></p>" . "\n";
            } else {
                echo "<p>Can't write to file $s</p>";
            }
        }
    }

    function show_used_functions_SS($parsed_file_ini, $variables, $text, $echo_html, $html_file_name, $write_in_file)
    {
        if (!isset($variables))
            return;

        $html = <<<_END
      <script src="jquery.js"></script>
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

        $id = str_replace(" ", "", $html_file_name);
        $id = str_replace(".", "", $html_file_name);
        $c = count($variables);
        $script = "var o = document.getElementById('" . $id . "'); if (o.style.display == 'block') {o.style.display = 'none'; document.getElementById(this.id).innerHTML = 'Show';} else { o.style.display = 'block';document.getElementById(this.id).innerHTML = 'Hide';}";
        $tr_even_odd = "tr:nth-child(even) {background: #eee} tr:nth-child(odd) {background: #FFF}";
        $html .= "<style>$tr_even_odd table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>";
        $html .= "<h1 style='color:black;'>$text</h1>";
        $html .= "<p><span id='S_$id' onclick=" . '"' . $script . '"' . "style='border:1px solid black;padding:3px;background-color:#eee;'>Show</span> Count: $c</p>";
        $display = 'none';
        if (($this->html_table_visible) && (!($variables === $this->parser_variables)))
            $display = 'block';
        $html .= "<table id='$id' style='display:$display;border:none;'>";

        $count = count($variables);
        if ($count > 0) {
            $variable = $variables[0];
            $html .= '<tr><th>#</th>';
            foreach ($variable as $key => $value) {
                $html .= '<th>' . strtolower(substr($this->_PHPI_CONSTANT_NAMES[$key], 6)) . '</th>';
//echo "$key => $value $html<br>";
            }
            $html .= '</tr><tr>' . "\n";
            for ($i = 0; $i < $count; $i++) {
//for ($i = 967; $i < $count-200; $i++) {
                $variable = $variables[$i];
                $html .= '<tr>';
                $html .= '<td>' . ($i + 0) . '</td>';
                foreach ($variable as $key => $value) {
                    if (is_array($value)) {
                        $html .= "<td><table><tr>";
                        foreach ($value as $data) {
                            if (is_array($data)) {
// parameters
                                $html .= "<td><table><tr>";
                                foreach ($data as $p) {
                                    $html .= "<td>$p</td>";
                                }
                                $html .= "</tr></table></td>";
                            } else {
                                $html .= "<td>$data</td>";
                            }
                        }
                        $html .= "</tr></table></td>";
                    } else {
                        if ($value === 'tainted')
                            $style = "style='color:red;'";
                        else if ($value === 'executed')
                            $style = "style='color:red;'";
                        else if ($value === 'user defined')
                            $style = "style='color:red;'";
                        else
                            $style = "";

// file name
//echo "$key $value<br>";
// echo $this->_PHPI_CONSTANT_NAMES[$key] . ' '. $value . '<br>';
                        if (strtolower(substr($this->_PHPI_CONSTANT_NAMES[$key], 6)) === 'file') {
                            $file_name = $this->files->files_tokens_names[$value];
                            $value = basename($this->files->files_tokens_names[$value]);
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
											
                            $value = "<a href='" . BASE_URL . "show_php_file.php?file=$file_name&line_mark=$line_mark&line_end=$line_end&variable_name=" . $variable_name . "&text=$text#target_mark'>$value</a>";
                        }
                        $html .= "<td $style>$value</td>";
                    }
                }
                $html .= '<tr>' . "\n";
            }
            $html .= '</table>' . "\n";
        } // count
        if ($echo_html) {
            echo $html;
        }
        if ($write_in_file) {
// the PHP parser file
            $parser_file_base_name = basename($this->files->files_tokens_names[0]);
            $s = './output/' . $parser_file_base_name . '_' . $html_file_name;
            $fs = fopen($s, "wt");
            if ($fs != null) {
                fprintf($fs, $html);
                fclose($fs);
                echo "<p><a href='$s'>$text</a></p>" . "\n";
            } else {
                echo "<p>Can't write to file $s</p>";
            }
        }
    }

    function show_variables($parsed_file_ini, $variables, $text, $echo_html, $html_file_name, $write_in_file)
    {
        if (!isset($variables))
            return array();

        $BASE_URL_VAR = BASE_URL;
				
        $html = "<script src='{$BASE_URL_VAR}jquery.js'/>";
        $html .= <<<_END
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
        //echo "ZXC show_variables " . count($variables) ."<hr>";
        /*
    $html3 = "<div id='$id' style='display:$display;border:none;'>" . "\n";
    $html1 = "<p><span id='S_$id' onclick=" . '"' . $script . '"' . "style='border:1px solid black;padding:3px;background-color:#eee;'>Show</span> Count: $number</p>" . "\n";
    $script = "var o = document.getElementById('" . $id . "'); if (o.style.display == 'block') {o.style.display = 'none'; document.getElementById(this.id).innerHTML = 'Show';} else { o.style.display = 'block';document.getElementById(this.id).innerHTML = 'Hide';}" . PHP_EOL;
  */
        $id = str_replace(" ", "", $html_file_name);
        $id = str_replace(".", "", $id);
        $id = str_replace(":", "", $id);
        $id = str_replace("/", "", $id);
        $c = count($variables);
        $script = "var o = document.getElementById('" . $id . "'); if (o.style.display == 'block') {o.style.display = 'none'; document.getElementById(this.id).innerHTML = 'Show';} else { o.style.display = 'block';document.getElementById(this.id).innerHTML = 'Hide';}";
        $tr_even_odd = "tr:nth-child(even) {background: #eee} tr:nth-child(odd) {background: #FFF}";
        $html .= "<style>$tr_even_odd table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>";
        $html .= "<h1 style='color:black;'>$text</h1>";
        $html .= "<p><span id='S_$id' onclick=" . '"' . $script . '"' . "style='border:1px solid black;padding:3px;background-color:#eee;'>Show</span> Count: $c</p>";
        $display = 'none';
        if (($this->html_table_visible) && (!($variables === $this->parser_variables)))
            $display = 'block';
        $html .= "<table id='$id' style='display:$display;border:none;'>";

        $count = count($variables);
        if ($count > 0) {
            $variable = $variables[0];
            $html .= '<tr><th>#</th> <th>Initial parsed file</th>';
            foreach ($variable as $key => $value) {
                $html .= '<th>' . strtolower(substr($this->_PHPI_CONSTANT_NAMES[$key], 6)) . '</th>';
//echo "$key => $value $html<br>";
            }
            $html .= '</tr><tr>' . "\n";
            for ($i = 0; $i < $count; $i++) {
//for ($i = 967; $i < $count-200; $i++) {
                $variable = $variables[$i];
                $html .= '<tr>';
                $html .= '<td>' . ($i + 0) . '</td>' . "<td>$parsed_file_ini</td>";
                foreach ($variable as $key => $value) {
                    if (is_array($value)) {
                        $html .= "<td><table><tr>";
                        foreach ($value as $data) {
                            if (is_array($data)) {
// parameters
                                $html .= "<td><table><tr>";
                                foreach ($data as $p) {
                                    $html .= "<td>$p</td>";
                                }
                                $html .= "</tr></table></td>";
                            } else {
                                $html .= "<td>$data</td>";
                            }
                        }
                        $html .= "</tr></table></td>";
                    } else {
                        if ($value === 'tainted')
                            $style = "style='color:red;'";
                        else if ($value === 'executed')
                            $style = "style='color:red;'";
                        else if ($value === 'user defined')
                            $style = "style='color:red;'";
                        else if (($value === 'SQL Injection') || ($value === 'Possible SQL Injection'))
                            $style = "style='background-color: lightgreen;'";
                        else if (($value === 'Cross Site Scripting') || ($value === 'Possible Cross Site Scripting'))
                            $style = "style='background-color: orangered;'";
                        else
                            $style = "";


                        $vv = '';
                        $value2 = '';
                        if (strtolower(substr($this->_PHPI_CONSTANT_NAMES[$key], 6)) === 'file') {
                            $vv = $variable[_PHPI_VULNERABILITY];
                            if (($vv == 'SQL Injection') || $vv == 'Possible SQL Injection')
                                $vv = "<span style='background-color: lightgreen;'>$vv</span>";
                            else if (($vv === 'Cross Site Scripting') || ($vv === 'Possible Cross Site Scripting'))
                                $vv = "<span style='background-color: orangered;'>$vv</span>";

                            $file_name = $this->files->files_tokens_names[$value];
                            //$value = basename($this->files->files_tokens_names[$value]);
                            $value = substr($this->files->files_tokens_names[$value], 0);
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
                            $variable_name = trim($variable_name);
                            $variable_name = str_replace(array('$', "'", '"'), array('%24', '%27', '%22'), $variable_name);

                            $dependence_variables = array("REQUEST", "POST", "GET");
                            $dependencies_index = $variable[_PHPI_DEPENDENCIES_INDEX];
                            if (isset($dependencies_index)) {
                                foreach ($dependencies_index as $kk => $dep_index) {
                                    $variable_name_dep = $this->parser_variables[$dep_index];
                                    $variable_name_dep = $variable_name_dep[_PHPI_NAME];
                                    //  echo "<p>_PHPI_DEPENDENCIES_INDEX: $dep_index  | $variable_name <-- $variable_name_dep </p>";
                                    $variable_name_dep = str_replace(array('$', "'", '"'), array('%24', '%27', '%22'), $variable_name_dep);
                                    $dependence_variables [] = $variable_name_dep;
                                }
                            }
                            $dependence_variables = urlencode(base64_encode(serialize($dependence_variables)));
                      
                         
                            $value = "<a href='" . BASE_URL . "show_php_file.php?file=$file_name&line_mark=$line_mark&line_end=$line_end&variable_name=" . $variable_name . "&text=$text&dependence_variables=$dependence_variables#target_mark'>$value</a>";

                            //$value = str_replace(array('$', "'", '"'), array('%24', '%27', '%22'), $value);

                            // sample lines of code
                            $name = $variable[_PHPI_NAME];
                            $line = $variable[_PHPI_LINE];
                            $tainted = $variable[_PHPI_TAINTED];
                            $cor = ($tainted === 'tainted') ? 'red' : 'green' . "; background-color: lightpink;";
                            $file_name = $this->files->files_tokens_names [$variable[_PHPI_FILE]];
                            $lines_of_code = $this->get_lines_of_code($file_name, $name, $line, -8, $cor)[0];
                            //$value2 = $lines_of_code;
                        }
                        $html .= "<td $style>$value $value2 </td>";
                    }
                }
                $html .= '<tr>';
            }
            $html .= '</table>';
        } // count
        if ($echo_html) {
            echo $html;
        }
        $s = $html_file_name;
        if ($write_in_file) {
            $fs = fopen($s, "wb");
            if ($fs != null) {

                fwrite($fs, $html, strlen($html));
                fclose($fs);
            } else {
                echo "<p>Can't write to file $s</p>";
            }
        }

        //echo "ZXC $html_file_name <br>";
        $r [0] = $html_file_name;
        $r [1] = $html;
        return $r;
    }

    /**
     * Constructor that call all the functions that perform the static analysis looking for vulnerabilities
     *
     * TODO check if PHP variables inside HTML code are double quoted
     * TODO dynamically created content
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     */

    /**
     * Parse the multi-dimensional array $files_tokens and calls
     * the functions that deal with the various code constructs.
     * This is done in a recursive manner, since many of those functions will call this function to parse their contents.
     * The outcome of this process is the multi-dimensional array $parser_variables with the PHP variables discovered during the parsing.
     * This includes information about variable tainting and vulnerabilities.
     *
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
     * @param string $block_end_index with the end index of tokens the the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the end of the multi-dimensional array $files_tokens
     * new
     *
     * $ISA[] - replaces calls to is_array() function
     *
     *
     * 2015-02-11
     * add $class_name parameter
     *
     */

    function main_parser($file_name, $class_name, $function_name, $block_start_index, $block_end_index)
    {
//$this->debug(sprintf("%s:%s:<span style='color:blue;'>%s</span> :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');
//$this->main_parser_level++;
//$this->debug("<b><span style='color:blue;'>Before main for</span></b>: " . $file_name . ' - <b>' . $block_start_index . ' - ' . $block_end_index . '</b><br />');
        if ($this->parser_debug2_flag)
            $this->debug2("Before main for($file_name, $block_start_index, $block_end_index)", 'Before main for($file_name, $block_start_index, $block_end_index)');
        if (is_null($file_name)) {
//point to the first php file
            reset($this->files->files_tokens);
            $file_name = key($this->files->files_tokens);
        }
        if (is_null($block_start_index)) {
            $block_start_index = 0;
        }
        if (is_null($block_end_index)) {
            $block_end_index = count($this->files->files_tokens[$file_name]) - 1;
        }
        if (is_null($function_name)) {
//the main function of the PHP code
            $function_name = 'function';
        }
        if ($this->parser_debug2_flag)
            $this->debug2("main_parser($file_name, $function_name, $block_start_index, $block_end_index)", 'main_parser($file_name, $function_name, $block_start_index, $block_end_index)');

        $tokens = $this->files->files_tokens[$file_name];
        $ISA = $this->files->files_tokens_is_array[$file_name];  // PN
//search every FileTokens
        for ($i = $block_start_index; $i < $block_end_index; $i++) {
//Array tokens
//$time_start = microtime(true);
//if (is_array($tokens[$i])) {   // JF
            if ($ISA[$i]) {   // PN
                $token = $tokens[$i][0];
//is non PHP code
                if (T_INLINE_HTML === $token) {
                    $i = $this->parse_non_php($file_name, $class_name, $function_name, $i);
//Loops: T_FOR T_FOREACH T_IF T_WHILE T_SWITCH
                } elseif (T_FOR === $token) {
                    $i = $this->parse_for($file_name, $class_name, $function_name, $i);
                } elseif (T_FOREACH === $token) {
                    $i = $this->parse_foreach($file_name, $class_name, $function_name, $i);
                } elseif (T_DO === $token) {
                    $i = $this->parse_do_while_do($file_name, $class_name, $function_name, $i);
                } elseif (T_WHILE === $token) {
                    $i = $this->parse_do_while_do($file_name, $class_name, $function_name, $i);
//Conditionals: T_IF
                } elseif ((T_IF === $token) || (T_ELSE === $token) || (T_ELSEIF === $token)) {
                    $i = $this->parse_if($file_name, $class_name, $function_name, $i);
//Conditionals: T_SWITCH
                } elseif (T_SWITCH === $token) {
                    $i = $this->parse_switch($file_name, $class_name, $function_name, $i);
//TODO T_GOTO
//T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE
                } elseif ((T_INCLUDE === $token) || (T_INCLUDE_ONCE === $token) || (T_REQUIRE === $token) || (T_REQUIRE_ONCE === $token)) {
                    $i = $this->parse_include_require($file_name, $class_name, $function_name, $i);
//Output
                } elseif ((T_ECHO === $token) || (T_PRINT === $token) || (T_EXIT === $token) || (T_INT_CAST === $token) || (T_DOUBLE_CAST === $token) || (T_STRING_CAST === $token) || (T_ARRAY_CAST === $token) || (T_OBJECT_CAST === $token) || (T_BOOL_CAST === $token) || (T_UNSET_CAST === $token)) {
                    $output_function = $this->parse_function_method($file_name, $class_name, $function_name, $i);
                    $i = $output_function[0];
//function call
                } elseif (($this->is_function($file_name, $i)) || ($this->is_method($file_name, $i))) {
                    $function_method = $this->parse_function_method($file_name, $class_name, $function_name, $i);
                    $i = $function_method[0];
//function definition should be skipped because it is executed when called in the PHP code
                } elseif (T_FUNCTION === $token) {
//skip this token
                    $i = $this->find_match($file_name, $i, '{');
//function return
                } elseif (T_RETURN === $token) {
                    $i = $this->parse_return($file_name, $class_name, $function_name, $i);

//TODO T_CURLY_OPEN
//local and global variables
                } elseif ((T_VARIABLE === $token) || (T_GLOBAL === $token) || (T_CONST === $token) || (($this->is_variable($file_name, $i)) || ($this->is_property($file_name, $i)))) {
                    $i = $this->parse_variable_property($file_name, $class_name, $function_name, $i);
//T_AND_EQUAL T_CONCAT_EQUAL T_DIV_EQUAL T_MINUS_EQUAL T_MOD_EQUAL T_MUL_EQUAL T_OR_EQUAL T_PLUS_EQUAL T_XOR_EQUAL T_SL_EQUAL T_SR_EQUAL
//$this->echo_h1("is $i", "green");
                } elseif ((T_AND_EQUAL === $token) || (T_CONCAT_EQUAL === $token) || (T_DIV_EQUAL === $token) || (T_MINUS_EQUAL === $token) || (T_MOD_EQUAL === $token) || (T_MUL_EQUAL === $token) || (T_OR_EQUAL === $token) || (T_PLUS_EQUAL === $token) || (T_XOR_EQUAL === $token) || (T_SL_EQUAL === $token) || (T_SR_EQUAL === $token)) {
// 2015-01-22, support T_NEW (T_NEW === $token) ||
                    $i = $this->parse_equal($file_name, $class_name, $function_name, $i);
//T_UNSET
                } elseif (T_UNSET === $token) {
                    $i = $this->parse_unset($file_name, $class_name, $function_name, $i);
                }
            } else {     //Non array tokens
                if ('=' === $tokens[$i]) {
                    $i = $this->parse_equal($file_name, $class_name, $function_name, $i);
                }
            }
//echo $i . "<br>";
// PN
//      if (($i < $block_start_index) || ($i > $block_end_index)) {
////            $code = "";
////             for ($k = $block_start_index; $k < $block_end_index; $k++) {
////                 $code .=  $bi= $token[$k][0][0];
////             }
////              echo $code;
//
//        $bs = $tokens[$block_start_index][0][0]; // . $token[$block_start_index][0][2];
//        $bi = $tokens[$i][0][0];
//        $bi_prev = $tokens[$i_prev][0][0];
//        if ($bi_prev > $bi)
//          $cor2 = 'red';
//        else
//          $cor2 = 'black';
//        $be = $tokens[$block_end_index][0][0];
//        $ss = "<td>begin: $bs</td> <td>i: $bi</td><td>i_prev: $bi_prev</td> <td>end: $be</td>";
//        $ss = "<tr>$ss<th style='color:red;'>[$block_start_index, $i_prev/<span style='$cor2'>$i</span>, $block_end_index</th></tr>";
//        if ($this->echo_debug === 1)
//          echo $ss;
//
//        if ($this->file_debug === 1) {
//          fprintf($this->text_file_stream, "%s", $ss);
//          fflush($this->text_file_stream);
//        }
//
//        //die();
//        // $i = $block_end_index;
//      }
//            if ($time >= $this->threshold_time_php_tag) {
////        $bs = $this->array_data_token_html_td($tokens[$block_start_index], 'green');
////        $bi = $this->array_data_token_html_td($tokens[$i], 'brown');
////        $be = $this->array_data_token_html_td($tokens[$block_end_index], 'red');
//                $hours = $time / 60 / 60;
//                $minutes = ($time - floor($hours) * 60 * 60) / 60;
//                $seconds = ($time - floor($hours) * 60 * 60 - floor($minutes) * 60);
//                $times = floor($hours) . ':' . floor($minutes) . ':' . floor($seconds);
//
//                if ($time > 60) {
//                    $cor = 'red';
//                } elseif ($time > 30) {
//                    $cor = 'brown';
//                } elseif ($time > 20) {
//                    $cor = 'blue';
//                } elseif ($time > 10) {
//                    $cor = 'green';
//                } else {
//                    $cor = 'black';
//                }
//                $time = sprintf("%5.2f", $time);
//                $pv = count($this->parser_variables);
//                $ss = "<tr><td>[$block_start_index, $i, $block_end_index]</td><td>$type</td><td style='color:$cor'>$time</td><td>PV: $pv</td></tr>";
//                if ($this->echo_debug === 1)
//                    echo $ss;
//
//                if ($this->file_debug === 1) {
//                    fprintf($this->text_file_stream, "%s", $ss);
//                    fflush($this->text_file_stream);
//                }
//
////
////        $s = "<tr><td style='text-align:right;'>After</td><td>$block_start_index</td><td>$i</td><td>$block_end_index</td>" . $bs . $bi . $be . '</tr>';
////         if ($this->echo_debug === 1)
////          echo $s;
////        if ($this->file_debug === 1) {
////        fprintf($this->text_file_stream, "%s", $s);
////        fflush($this->text_file_stream);
////        }
//            }
        } // for
// $this->main_parser_level--;
// $time = microtime(true) - $this->start_time;
// $mu = intval(memory_get_usage() / 1024.0);
// echo "$time $mu Kb<br>";
    }

    function __construct($file_name)
    {
        // 2015-01-21
        $this->_PHPI_CONSTANT_NAMES = array(
            "_PHPI_INDEX",
            "_PHPI_NAME",
            "_PHPI_OBJECT",
            '_PHPI_CLASS',
            "_PHPI_SCOPE",
            "_PHPI_VARIABLE_FUNCTION",
            "_PHPI_EXIST_DESTROYED",
            "_PHPI_CODE_TYPE",
            "_PHPI_INPUT",
            "_PHPI_OUTPUT",
            "_PHPI_FUNCTION",
            "_PHPI_FILE",
            "_PHPI_LINE",
            "_PHPI_TAINTED",
            "_PHPI_VULNERABILITY",
            "_PHPI_START_INDEX",
            "_PHPI_END_INDEX",
            "_PHPI_DEPENDENCIES_INDEX",
            "_PHPI_VARIABLE_FILTER",
            "_PHPI_VARIABLE_REVERT_FILTER",
            '_PHPI_SENSITIVE_SINK',
            '_PHPI_SENSITIVE_SINK_VULNERABILITY',
            "_PHPI_PARAMETERS",
            '_PHPI_EXECUTED',
            '_PHPI_START_LINE',
            '_PHPI_END_LINE',
            '_PHPI_CALLED_FUNCTIONS',
            '_PHPI_START_PARAMETER_INDEX',
            '_PHPI_END_PARAMETER_INDEX',
            '_PHPI_USER_DEFINED', '_PHPI_FILTER', '_PHPI_REVERT_FILTER', '_PHPI_OTHER',
            '_PHPI_PARAMETER_NAME',
            '_PHPI_METHOD_COMPLETE_NAME', '_PHPI_COUNT'
        );
        $n = 0;
        foreach ($this->_PHPI_CONSTANT_NAMES as $value) {
            if (!defined($value)) {
                define($value, intval($n++));
            }
        }
        // set debug and output options
        $this->output_check_array = array('tokens_array_of_arrays', 'resume_report', 'vulnerable_variables',
            'vulnerable_variables_with_dependencies',
            // 'vulnerable_variables_tree',
            'output_variables',
            'file_functions',
            'used_functions',
            'file_classes',
            'files_include_require',
            'parser_variables',
            'parser_variables_lookup');

        $this->files = new Php_File($file_name);
        //$this->start_time = microtime(true);
        //only analyze the file if the file exists
        if (!is_null($this->files->files_tokens)) {
            if ($this->parser_debug2_flag) {
//$this->parser_debug2_file_stream = fopen(basename($file_name) . "_debug.html", "wt");
                $s = "<style> table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>";
            }
            if ($this->parser_debug2_flag_file) {
                $s = "<style> table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>";
//$this->parser_debug2_file_stream = fopen('/PARSER/' . basename($file_name) . "_debug.html", "wt");
                $this->parser_debug2_file_stream = fopen($this->parser_debug2_file_path . basename($file_name) . "_debug.html", "wt");
                fprintf($this->parser_debug2_file_stream, "%s", $s);
                fprintf($this->parser_debug2_file_stream, "%s", "<table>");
                $ss = $this->parser_debug2_file_path . basename($file_name) . "_debug.html";
                echo "<p><a href='$ss'>$ss</a></p>";
            }

//add all the user defined functions to the multi-dimensional array $filesFunctions
            $this->include_all_php_files_functions();
// OOP
            $this->include_all_php_files_classes();
            if ($this->echo_debug === 1) {
                echo "Total functions: " . (count($this->files_functions) - 1);
            }
            $ini = (count($this->files_functions) - 1);
            $fim = 121;

            $s = date('Y-m-d_H_i_s', time());
            $s .= '-' . gethostname();
            $s = "";  //./output/
//$this->text_file_stream = fopen("functions_call-$s-$ini-$fim.html", "wt");
            if ($this->file_debug === 1) {
                $this->text_file_stream = fopen('./output/' . basename($file_name) . "_functions_call.html", "wt");
            }
//            if ($this->file_write_tokens_array_of_arrays) {
//                $s = './output/' . basename($file_name) . "_Tokens_array_of_arrays" . ".html";
//                $this->write_tokens_array_of_arrays($s, $this->files->files_tokens);
//                echo "<p><a href='$s'>Files_tokens</a></p>";
//            }
//      if ($this->echo_debug === 1) {
//        $s = "<h1>From: $ini To: $fim</h1>";
//        echo $s;
//      }
            if ($this->file_debug === 1) {
                fprintf($this->text_file_stream, "%s", $s);
                fprintf($this->text_file_stream, "%s", '<table>');
            }
            if ($this->echo_debug === 1) {
                echo '<table>';
            }
// <meta http-equiv='refresh' content='60'>
            $s = "<head>" . "<style> table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>" . "</head>";

            if ($this->echo_debug === 1) {
                echo $s;
            }
            if ($this->file_debug === 1) {
                fprintf($this->text_file_stream, "%s", $s);
                fflush($this->text_file_stream);
            }
            $ef = 0;
            if ($this->echo_debug === 1) {
                $ef++;
            }
            if ($this->file_debug === 1) {
                $ef++;
            }

// begins with the functions that do not calls any user defined function.
// function 0 is 'function'
            $geral_time_start = microtime(true);
//parse all the functions that are not executed
            for ($i = (count($this->files_functions) - 1); $i > 0; $i--) {
                if (('not executed' === $this->files_functions[$i][_PHPI_EXECUTED]) && ('function' != $this->files_functions[$i][_PHPI_NAME])) {
                    $file_name = $this->files_functions[$i][_PHPI_FILE];
                    $class_name = $this->files_functions[$i][_PHPI_CLASS];
                    $function_name = $this->files_functions[$i][_PHPI_NAME];
                    $block_start_index = $this->files_functions[$i][_PHPI_START_INDEX];
                    $block_start_index = $this->find_token($file_name, $block_start_index, '{');
                    $block_end_index = $this->files_functions[$i][_PHPI_END_INDEX];
//parse the PHP files and searches for vulnerabilities. Adds the variables to the multi-dimensional array $parser_variables
                    $time_start = microtime(true);
                    $this->main_parser($file_name, $class_name, $function_name, $block_start_index, $block_end_index);

                    if ($ef > 0) {
                        $time_end = microtime(true);
                        $time = $time_end - $time_start;

                        $ss = sprintf("%8.3f", $this->pn_count_function_get_variable_index / 1000.0);
                        $ss2 = sprintf("%8.4f", $this->time_function_get_variable_index);
                        $ss = "<tr><td>pn_count_function_get_variable_index</td><td>$ss K</td><td>$ss2 seg</td></tr>";
                        if ($this->echo_debug === 1) {
                            echo $ss;
                        }
                        if ($this->file_debug === 1) {
                            fprintf($this->text_file_stream, "%s", $ss);
                            fflush($this->text_file_stream);
                        }

                        $ss = $this->files_functions[$i][_PHPI_NAME];
                        $ss = "<tr><th>level: $this->main_parser_level</th><td>$ss</td></tr>";
                        if ($this->echo_debug === 1) {
                            echo $ss;
                        }
                        if ($this->file_debug === 1) {
                            fprintf($this->text_file_stream, "%s", $ss);
                            fflush($this->text_file_stream);
                        }
                        if ($this->echo_debug === 1) {
                            echo $ss;
                        }
                        if ($this->file_debug === 1) {
                            fprintf($this->text_file_stream, "%s", $ss);
                            fflush($this->text_file_stream);
                        }

                        $callf = "";
                        $hours = $time / 60 / 60;
                        $minutes = ($time - floor($hours) * 60 * 60) / 60;
                        $seconds = ($time - floor($hours) * 60 * 60 - floor($minutes) * 60);
                        $times = floor($hours) . ':' . floor($minutes) . ':' . floor($seconds);

                        if ($time > 60) {
                            $cor = 'red';
                        } elseif ($time > 30) {
                            $cor = 'blue';
                        } else {
                            $cor = 'black';
                        }
                        $mu = intval(memory_get_usage() / 1024.0 / 1024.0);

                        $na = count($this->files_functions);
                        $nb = count($this->files->files_tokens);
                        $nc = count($this->used_functions);
                        $nd = count($this->functions_stack);
// array 2-dims
                        $cf = count($this->files_functions[$i][_PHPI_CALLED_FUNCTIONS]);
                        $pv = count($this->parser_variables);
                        $pd = count($this->parser_debug);

                        $pd = count($this->parser_debug);
                        $ss = "called functions: $cf /parser_variables: $pv /parser_debug: $pd /$na/$nb/$nc/$nd";

                        $ss = "<tr><td>$callf</td><td>Mb: $mu</td><th><span style='color:$cor;'>$i</span></th><td>" . $this->files_functions[$i][_PHPI_NAME] .
                            "</td><td>$times</td><td style='text-align:right;color:$cor;'>" . sprintf('%01.2f', $time) .
                            "</td><td>$ss</td></tr>";

                        if ($this->echo_debug === 1) {
                            echo $ss;
                        }
                        flush();
                        if ($this->file_debug === 1) {
                            fprintf($this->text_file_stream, "%s", $ss);
                            fflush($this->text_file_stream);
                        }
                    }
                } else {
                    if ($ef > 0) {
                        $ss = $this->files_functions[$i][_PHPI_NAME];
                        $ss = "<tr><th>$i</th><td>$ss</td><td>not executed</td></tr>";

                        if ($this->echo_debug === 1) {
                            echo $ss;
                        }
                        if ($this->file_debug === 1) {
                            fprintf($this->text_file_stream, "%s", $ss);
                            fflush($this->text_file_stream);
                        }
                    }
                }
            }
            if ($ef > 0) {
                $time_end = microtime(true);
                $time = $time_end - $geral_time_start;

                $hours = $time / 60 / 60;
                $minutes = ($time - floor($hours) * 60 * 60) / 60;
                $seconds = ($time - floor($hours) * 60 * 60 - floor($minutes) * 60);
                $times = floor($hours) . ':' . floor($minutes) . ':' . floor($seconds);

                $s = "<tr><th colspan='3' style='text-align:right;'>$times</b></th><th>" . sprintf('%01.2f', $time) . "</th></tr>";

                if ($this->echo_debug === 1) {
                    echo $s;
                }
                if ($this->file_debug === 1) {
                    fprintf($this->text_file_stream, "%s", $s);
                }
            }


//print_r($a);
//      print_r($this->files->files_tokens[$file_name]);
//      die();
//parse the PHP files and searches for vulnerabilities. Adds the variables to the multi-dimensional array $parser_variables
//$this->pn_count_function_get_variable_index = 0;
//$this->time_function_get_variable_index = 0.0;


            $this->main_parser(null, null, null, null, null);

            if ($ef > 0) {
                $ss = sprintf("%8.3f", $this->pn_count_function_get_variable_index / 1000.0);
                $ss2 = sprintf("%8.4f", $this->time_function_get_variable_index);
                $ss = "<tr><td>pn_count_function_get_variable_index</td><td>$ss K</td><td>$ss2 seg</td></tr>";

                if ($this->echo_debug === 1) {
                    echo $ss;
                }
                if ($this->file_debug === 1) {
                    fprintf($this->text_file_stream, "%s", $ss);
                    fflush($this->text_file_stream);
                    fprintf($this->text_file_stream, "%s", '</table>');
                }
                echo '</table>';
            }


//add the vulnerable variables to the multi-dimensional array $vulnerable_variables
            $this->set_vulnerable_variables();
            $this->set_non_vulnerable_variables();
//add the output variables to the multi-dimensional array $output_variables
            $this->set_output_variables();

            if ($this->parser_debug2_flag) {
                $s = "<style> table, td, th {padding:4px; border: 1px solid black;border-collapse: collapse;}</style>";
                echo "$s<h1>Debug table</h1><table>$this->parser_debug2_text</table>";
                if ($this->parser_debug2_flag_file) {
                    fprintf($this->parser_debug2_file_stream, "%s", "$s<h1>Debug table</h1><table>$this->parser_debug2_text</table>");
                    fclose($this->parser_debug2_file_stream);
                }
            }
        } // for

        $time = $this->time_execution_of;
        $timeg = microtime(true) - $this->start_time;
        $perc = 0;
        if ($timeg > 0) {
            $perc = $time / (1.0 * $timeg) * 100.0;
        }
        $P = $perc;

        $perc = sprintf('%01.3f', $perc);
        $time = sprintf('%01.4f', $time);
        $timeg = sprintf('%01.5f', $timeg);

//    if ($P >= 5.0)
//      echo "<h1 style='color:blue;'>php_ $timeg  $time $perc% </h1>";
//    else
//      echo "<h1 style='color:green;'>php_ $timeg  $time $perc% </h1>";
//
//    echo count($this->files->find_match_array_);
//    if (is_array($this->files->find_match_array_)) {
//      foreach ($this->files->find_match_array_ as $key => $token) {
//        echo "<p'> $key => $token </p>";
//      }
//    }
//    $c = $this->count_execution;
//    echo "<h1 style='color:blue;'>count execution:  $c </h1>";

        $s = "<h2>End of analysis</h2>";
        if ($this->echo_debug === 1) {
            echo $s;
        }

        if ($this->file_debug === 1) {
            fprintf($this->text_file_stream, "%s", $s);
            fclose($this->text_file_stream);
        }
    }

// function

    /**
     * For all the PHP files included in the multi-dimensional array $files_tokens
     * calls the function includePhpFilesFunctions that adds the user defined functions
     * to the multi-dimensional array $filesFunctions.
     */
    function include_all_php_files_functions()
    {
//loop through all the PHP file names
        foreach ($this->files->files_tokens as $file_name => $dummy) {
            $this->include_php_files_functions($file_name);
        }
		if (is_array($this->files_functions)) {
			$count_this_files_functions = count($this->files_functions);
		} else {
			$count_this_files_functions = 0;
		}
		
        for ($i = 0, $count = $count_this_files_functions; $i < $count; $i++) {
			if (is_array ($this->files_functions[$i][_PHPI_CALLED_FUNCTIONS])) {
			$count_this_files_functions_PHPI_CALLED_FUNCTIONS = count($this->files_functions[$i][_PHPI_CALLED_FUNCTIONS]); 
		}   else {
			$count_this_files_functions_PHPI_CALLED_FUNCTIONS = 0;
		}
            for ($j = 0, $jcount = $count_this_files_functions_PHPI_CALLED_FUNCTIONS; $j < $jcount; $j++) {
                $called_function_name = $this->files_functions[$i][_PHPI_CALLED_FUNCTIONS][$j][_PHPI_NAME];
//add the function to the $used_functions array
                $called_class_name = $this->files_functions[$i][_PHPI_CALLED_FUNCTIONS][$j][_PHPI_CLASS];
                $called_file_name = $this->files_functions[$i][_PHPI_CALLED_FUNCTIONS][$j][_PHPI_FILE];
//$this->add_used_functions($called_function_name); // Original
                $this->add_used_functions($called_file_name, $called_class_name, $called_function_name);
            }
        }
    }

    /**
     * For all the PHP files included in the multi-dimensional array $files_tokens
     * calls the function includePhpFilesFunctions that adds the user defined classes
     * to the multi-dimensional array $files_classes.
     */
    function include_all_php_files_classes()
    {
        return;
    }

    /**
     *
     * @return type
     */
    function find_class_name()
    {
        return null;
    }

    /**
     *
     * @param type $tokens
     * @return type
     */
    function get_last_number_line_of_file($tokens, $end_index)
    {
        $file_end_function_line = 0;
        for ($k = $end_index; $k >= 0; $k--) {
            if (is_array($tokens[$k])) {
                $file_end_function_line = $tokens[$k][2];
                break;
            }
        }
        return $file_end_function_line;
    }

    /**
     * Search the contents of the multi-dimensional array $files_tokens for user defined functions
     * and add them to the multi-dimensional array $files_classes.
     *
     * TODO functions defined inside other functions
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     */
    function include_php_files_functions($file_name)
    {
//$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');
        if ($this->parser_debug2_flag)
            $this->debug2("include_php_files_functions($file_name)", 'include_php_files_functions($file_name)');

        $called_functions = null;
        //generate an array of the function calls
        $tokens = $this->files->files_tokens[$file_name];
        for ($i = 0, $count = count($tokens); $i < $count; $i++) {
            $t = $tokens[$i][0];
            if ((T_ECHO === $t) || (T_PRINT === $t) || (T_EXIT === $t) || (T_INT_CAST === $t) || (T_DOUBLE_CAST === $t) || (T_STRING_CAST === $t) || (T_ARRAY_CAST === $t) || (T_OBJECT_CAST === $t) || (T_BOOL_CAST === $t) || (T_UNSET_CAST === $t) || ($this->is_function($file_name, $i)) || ($this->is_method($file_name, $i))) {
                //calculate the end token of the function call
                $called_function_name = $this->get_function_method_name($file_name, $i);
                $start_index = $i;
                $i = $this->get_variable_property_function_method_last_index($file_name, $i);

                $called_class_name = "UNKNOWN";
                //$called_file_name = "UNKNOWN";
                $called_file_name = $file_name;

//        if (( T_ECHO === $t) || ( T_PRINT === $t ) || ( T_EXIT === $t ) || ( T_INT_CAST === $t ) || ( T_DOUBLE_CAST === $t ) || ( T_STRING_CAST === $t ) || ( T_ARRAY_CAST === $t ) || ( T_OBJECT_CAST === $t ) || ( T_BOOL_CAST === $t ) || ( T_UNSET_CAST === $t )) {
//            $called_class_name = "";
//        } else {
//        //  || ($this->is_function($file_name, $i)) || ($this->is_method($file_name, $i))
//          $called_class_name = "";
//        }

								// Begin: new ont 2016-11-30
								// get the name of the parameter os the function that a user defined function calls
								$function_parameters_new = null; //some functions may have no parameters
								$function_parameters_new_list = ''; 
								$file_token_function_start_parameter_index_new = $this->find_token($file_name, $i, '(');
								$file_token_function_end_parameter_index_new = $this->find_match($file_name, $file_token_function_start_parameter_index_new, '(');
								for ($jnew = $file_token_function_start_parameter_index_new; $jnew < $file_token_function_end_parameter_index_new; $jnew++) {
										if (($this->is_variable($file_name, $jnew)) || ($this->is_property($file_name, $jnew))) {
												$function_parameters_new[] = array(
														_PHPI_PARAMETER_NAME => $tokens[$jnew][1],
														_PHPI_LINE => $tokens[$jnew][2],
												);
												if ($function_parameters_new_list =='')
													$function_parameters_new_list .= $tokens[$jnew][1];
												else
												$function_parameters_new_list .= ', ' .$tokens[$jnew][1];
										}
								}
								// echo "<p>{$tokens[$i][2]} $called_function_name $function_parameters_new_list</p>";
								// echo "<p>";
								// print_r ($function_parameters_new);
								// echo "</p>";
								// End: new ont 2016-11-30

                $called_functions[] = array(
                    _PHPI_FILE => $called_file_name,
                    _PHPI_CLASS => $called_class_name, // TODO: object of classe X - determinate context.
                    _PHPI_NAME => $called_function_name,
                    // _PHPI_START_LINE => $tokens[$i][2],
                    _PHPI_LINE => $tokens[$i][2],   // 2016-11-27
                    _PHPI_START_INDEX => $start_index,
                    _PHPI_METHOD_COMPLETE_NAME => $called_function_name, // OOP - object creat
										_PHPI_PARAMETERS => $function_parameters_new
                );
            } elseif (T_FUNCTION === $tokens[$i][0]) {
                //skip this token
                $i = $this->find_match($file_name, $i, '{'); // JF
            }
        }

//find the last file line number of the $file_name
        $file_end_function_line = $this->get_last_number_line_of_file($tokens, count($tokens) - 1);
//    for ($k = $count - 1; $k >= 0; $k--) {
//      if (is_array($tokens[$k])) {
//        $file_end_function_line = $tokens[$k][2];
//        break;
//      }
//    }


        $class_name = ""; //$this->find_class_name();
//Add the function data to the Multi-dimensional associative array $files_functions
// Change PN
        //Classnames in PHP are not case sensitive (that doesn't depend on the operating system)
        $key = strtoupper("$file_name#$class_name#function");
//$key = strtoupper('function');
        $this->files_functions_lookup["$key"] = (is_array($this->files_functions)) ? count($this->files_functions):0;
// To.
        $this->files_functions[] = array(
            _PHPI_NAME => 'function',
            _PHPI_FILE => $file_name,
            _PHPI_CLASS => $class_name,
            _PHPI_EXECUTED => 'executed',
            _PHPI_START_LINE => 1, // old: 0
            _PHPI_END_LINE => $file_end_function_line,
            _PHPI_START_INDEX => 0,
            _PHPI_END_INDEX => $count - 1,
            _PHPI_PARAMETERS => null,
            _PHPI_CALLED_FUNCTIONS => $called_functions,
            _PHPI_START_PARAMETER_INDEX => -1, // new PN
            _PHPI_END_PARAMETER_INDEX => -1, // new PN
            _PHPI_METHOD_COMPLETE_NAME => $key      // new OOP
        );

// user defined function and methods
        $class_start_index = -1;
        $class_end_index = -1;
        $this->files_classes = array();
        for ($i = 0, $count = count($tokens); $i < $count; $i++) {
            $file_token_start_function_index = 0;
            $file_token_end_function_index = 0;
            $file_start_function_line = 0;
            $file_end_function_line = 0;
            $function_name = null;

// OOP
            if (is_array($tokens[$i]) && (T_CLASS === $tokens[$i][0])) {
                $class_start_index = $i;
                $class_end_index = $this->find_match($file_name, $i, '{');
//find the last file line number of the called function
//        $file_end_class_line = 0;
//        for ($k = $class_end_index - 1; $k >= 0; $k--) {
//          if (is_array($tokens[$k])) {
//            $file_end_class_line = $tokens[$k][2];
//            break;
//          }
//        }
                $file_end_class_line = $this->get_last_number_line_of_file($tokens, $class_end_index - 1);

                $this->files_classes [] = array(
                    _PHPI_NAME => $tokens[$i + 1][1], // classe name: class name {
                    _PHPI_FILE => $file_name,
                    _PHPI_EXECUTED => 'not executed',
                    _PHPI_START_LINE => $tokens[$i + 1][2],
                    _PHPI_END_LINE => $file_end_class_line,
                    _PHPI_START_INDEX => $class_start_index,
                    _PHPI_END_INDEX => $class_end_index
                );
            }

//Start of a function definition
            if (is_array($tokens[$i]) && (T_FUNCTION === $tokens[$i][0])) {

                $file_token_start_function_index = $i;
                $function_name = $this->get_function_method_name($file_name, $i + 1);
                $i = $this->get_variable_property_function_method_last_index($file_name, $i + 1);
                $file_token_end_function_index = $this->find_match($file_name, $i, '{');


                //$his->c

                if (!isset($tokens[$i][2])) {
                    echo $this->generate_code_from_tokens($this->files->files_tokens[$file_name], $i - 2, $i + 10) . '</p>';
                    $this->echo_h1("$function_name $file_start_function_line $file_token_start_function_index", 'blue');
                    $this->echo_h1($this->files->files_tokens_names[$file_name], 'red');

                    // die("$i..");
                }

                $file_start_function_line = $tokens[$i][2];

//generate an array of the function parameters
                $function_parameters = null; //some functions may have no parameters
                $file_token_function_start_parameter_index = $this->find_token($file_name, $i, '(');
                $file_token_function_end_parameter_index = $this->find_match($file_name, $file_token_function_start_parameter_index, '(');
                for ($j = $file_token_function_start_parameter_index; $j < $file_token_function_end_parameter_index; $j++) {
                    if (($this->is_variable($file_name, $j)) || ($this->is_property($file_name, $j))) {
                        $function_parameters[] = array(
                            _PHPI_PARAMETER_NAME => $tokens[$j][1],
                            _PHPI_LINE => $tokens[$j][2],
                        );
                    }
                }

                $called_functions = null;
//generate an array of the function calls
                for ($j = $file_token_function_start_parameter_index; $j < $file_token_end_function_index; $j++) {
                    $token = $tokens[$j][0];
                    if ((T_ECHO === $token) || (T_PRINT === $token) || (T_EXIT === $token) || (T_INT_CAST === $token) || (T_DOUBLE_CAST === $token) || (T_STRING_CAST === $token) || (T_ARRAY_CAST === $token) || (T_OBJECT_CAST === $token) || (T_BOOL_CAST === $token) || (T_UNSET_CAST === $token) || ($this->is_function($file_name, $j)) || ($this->is_method($file_name, $j))) {
//calculate the end token of the function call
                        $called_function_name = $this->get_function_method_name($file_name, $j); // back: PN
                        $called_class_name = "UNKNOWN";
                        //$called_file_name = "UNKNOWN";
                        $called_file_name = $file_name;
                        $called_key = strtoupper("$called_file_name#$called_class_name#$called_function_name");

												// Begin: new ont 2016-11-30
												// get the name of the parameter os the function that a user defined function calls
												$function_parameters_new = null; //some functions may have no parameters
												$function_parameters_new_list = ''; 
												$file_token_function_start_parameter_index_new = $this->find_token($file_name, $j, '(');
												$file_token_function_end_parameter_index_new = $this->find_match($file_name, $file_token_function_start_parameter_index_new, '(');
												for ($jnew = $file_token_function_start_parameter_index_new; $jnew < $file_token_function_end_parameter_index_new; $jnew++) {
														if (($this->is_variable($file_name, $jnew)) || ($this->is_property($file_name, $jnew))) {
																$function_parameters_new[] = array(
																		_PHPI_PARAMETER_NAME => $tokens[$jnew][1],
																		_PHPI_LINE => $tokens[$jnew][2],
																);
																if ($function_parameters_new_list =='')
																	$function_parameters_new_list .= $tokens[$jnew][1];
																else
																$function_parameters_new_list .= ', ' .$tokens[$jnew][1];
														}
												}
												// echo "<p>{$tokens[$j][2]} $called_function_name $function_parameters_new_list</p>";
												// echo "<p>";
												// print_r ($function_parameters_new);
												// echo "</p>";
												// End: new ont 2016-11-30
												
                        $called_functions[] = array(
                            _PHPI_NAME => $called_function_name,
                            _PHPI_FILE => $called_file_name,
                            _PHPI_CLASS => $called_class_name,
                            _PHPI_LINE => $tokens[$j][2],
                            _PHPI_START_INDEX => $j,
                            _PHPI_METHOD_COMPLETE_NAME => $called_key,  // OOP - object creation
														_PHPI_PARAMETERS => $function_parameters_new
                        );
												
											
                        $j = $this->get_variable_property_function_method_last_index($file_name, $j);
                    } elseif (T_FUNCTION === $token) {
//skip this token
                        $j = $this->find_match($file_name, $j, '{');
                    }
                }

//find the last file line number of the called function
//        $file_end_function_line = $file_start_function_line;
//        for ($k = $file_token_end_function_index; $k >= 0; $k--) {
//          if (is_array($tokens[$k])) {
//            $file_end_function_line = $tokens[$k][2];
//            break;
//          }
//        }
                $file_end_function_line = $this->get_last_number_line_of_file($tokens, $file_token_end_function_index);

// class ..... }
                if (($i > $class_start_index) && ($i < $class_end_index)) {
//echo " $i ";
                    $class_name = $this->files_classes[count($this->files_classes) - 1][_PHPI_NAME];
                } else {
                    $class_name = "";
                }
                $class_name = "UNKNOWN";

//Add the function data to the Multi-dimensional associative array $filesFunctions
// Change PN
                $key = strtoupper("$file_name#$class_name#$function_name");
//$key = strtoupper($function_name);
                $this->files_functions_lookup["$key"] = count($this->files_functions);
// To.
                $this->files_functions[] = array(
                    _PHPI_NAME => $function_name, // OK
                    _PHPI_FILE => $file_name, // OK
                    _PHPI_CLASS => $class_name, // OK
                    _PHPI_EXECUTED => 'not executed',
                    _PHPI_START_LINE => $file_start_function_line,
                    _PHPI_END_LINE => $file_end_function_line,
                    _PHPI_START_INDEX => $file_token_start_function_index,
                    _PHPI_END_INDEX => $file_token_end_function_index,
                    _PHPI_PARAMETERS => $function_parameters,
                    _PHPI_CALLED_FUNCTIONS => $called_functions,
                    _PHPI_START_PARAMETER_INDEX => $file_token_function_start_parameter_index, // new PN
                    _PHPI_END_PARAMETER_INDEX => $file_token_function_end_parameter_index, // new PN
                    _PHPI_METHOD_COMPLETE_NAME => $key   // new OOP
                );

//unset the $functionParameters array but keep the indexes untouched
                unset($function_parameters);
            }
        }

        // determinate the context of the function calls: called_file_name and called_class_name
        // adds to files_functions_lookup[]
        if (is_array ($this->files_functions)) {
			$count_this_files_functions = count($this->files_functions); 
		}   else {
			$count_this_files_functions = 0;
		}
        for ($i = 0, $count = $count_this_files_functions; $i < $count; $i++) {
			if (is_array ($this->files_functions[$i][_PHPI_CALLED_FUNCTIONS])) {
				$count_this_files_functions_PHPI_CALLED_FUNCTIONS = count($this->files_functions[$i][_PHPI_CALLED_FUNCTIONS]); 
			}   else {
				$count_this_files_functions_PHPI_CALLED_FUNCTIONS = 0;
			}
            for ($j = 0, $jcount = $count_this_files_functions_PHPI_CALLED_FUNCTIONS; $j < $jcount; $j++) {
                //$called_function_name = strtoupper($this->files_functions[$i][_PHPI_CALLED_FUNCTIONS][$j][_PHPI_NAME]);
//        for ($k = 0; $k < $count; $k++) {
//          if ($this->files_functions[$k][_PHPI_NAME] === $called_function_name) {
//            //echo "<h1>$count</h1>";
//            $this->files_functions[$k][_PHPI_EXECUTED] = 'executed';
//            break;
//          }
//        }
                $key = strtoupper($this->files_functions[$i][_PHPI_CALLED_FUNCTIONS][$j][_PHPI_METHOD_COMPLETE_NAME]);
                if (isset($this->files_functions_lookup["$key"])) {
                    $k = $this->files_functions_lookup["$key"];
                    $this->files_functions[$k][_PHPI_EXECUTED] = 'executed';
                    //$this->echo_h1("$key $k", 'red');
                }
            }
        }
    }

    /**
     * Add used functions to the Multi-dimensional associative array with all the functions used in the code.
     *
     * @param string $called_function_name with the name of the function
     *
     */
//function add_used_functions($called_function_name) {
    function add_used_functions($file_name, $class_name, $called_function_name)
    {
//add the function to the $used_functions array
//old
//    for ($i = 0, $count = count($this->used_functions); $i < $count; $i++) {
//      if (0 === strcasecmp($this->used_functions[$i][_PHPI_NAME], $called_function_name)) {
//        break;
//      }
//    }
// old

        $key_completed_name = strtoupper("$file_name#$class_name#$called_function_name");
        //$this->echo_h1($key_completed_name, 'red');
        if (isset($this->used_functions_lookup["$key_completed_name"])) {
            $i = $this->used_functions_lookup["$key_completed_name"];
            $this->used_functions[$i][_PHPI_COUNT]++;
            return;
        }
        $count = is_array($this->used_functions) ? count($this->used_functions):0;  

// old
//      for ($i = 0, $count = count($this->files_functions); $i < $count; $i++) {
//        if (0 === strcasecmp($this->files_functions[$i][_PHPI_NAME], $called_function_name)) {
//          $function_user_defined = 'user defined';
//          break;
//        }
//      }
// old
        $function_user_defined = 'not user defined';
        if (isset($this->files_functions_lookup["$key_completed_name"])) {
            $function_user_defined = 'user defined';
        }
        $function_input = 'not input';
        foreach (Vulnerable_Input::$INPUT_FUNCTIONS as $key => $value) {
//foreach ($INPUT_FUNCTIONS as $key => $value) {
            foreach ($value as $output) {
//note: PHP functions are not case sensitive
                if (0 === strcasecmp($output, $called_function_name)) {
                    $function_input = 'input';
                    break;
                }
            }
        }

        $function_output = 'not output';
        $vulnerability = 'none';
        foreach (Vulnerable_Output::$OUTPUT_FUNCTIONS as $key => $value) {
//foreach ($OUTPUT_FUNCTIONS as $key => $value) {
            foreach ($value as $output) {
//note: PHP functions are not case sensitive
                if (0 === strcasecmp($output, $called_function_name)) {
                    $function_output = 'output';
                    $vulnerability = $key;
                    break;
                }
            }
        }

        $function_filter = 'not filter';
        foreach (Vulnerable_Filter::$VARIABLE_FILTERS as $key => $value) {
//foreach ($VARIABLE_FILTERS as $key => $value) {
            foreach ($value as $output) {
//note: PHP functions are not case sensitive
                if (0 === strcasecmp($output, $called_function_name)) {
                    $function_filter = 'filter';
                    break;
                }
            }
        }

        $function_revert_filter = 'not revert filter';
        foreach (Vulnerable_Filter::$REVERT_VARIABLE_FILTERS as $key => $value) {
//foreach ($REVERT_VARIABLE_FILTERS as $key => $value) {
            foreach ($value as $output) {
//note: PHP functions are not case sensitive
                if (0 === strcasecmp($output, $called_function_name)) {
                    $function_revert_filter = 'revert filter';
                    break;
                }
            }
        }

        $function_other = 'other';
        if (('user defined' === $function_user_defined) || ('input' === $function_input) || ('output' === $function_output) || ('filter' === $function_filter) || ('revert filter' === $function_revert_filter)
        ) {
            $function_other = 'not other';
        }

        $this->used_functions[] = array(
            _PHPI_NAME => $called_function_name,
            _PHPI_FILE => $file_name,
            _PHPI_CLASS => $class_name,
            _PHPI_USER_DEFINED => $function_user_defined,
            _PHPI_COUNT => 1,
            _PHPI_INPUT => $function_input,
            _PHPI_OUTPUT => $function_output,
            _PHPI_VULNERABILITY => $vulnerability,
            _PHPI_FILTER => $function_filter,
            _PHPI_REVERT_FILTER => $function_revert_filter,
            _PHPI_OTHER => $function_other
        );
// Change
        $this->used_functions_lookup["$key_completed_name"] = count($this->used_functions) - 1;
// To.
    }

    /**
     * create the multi-dimensional associative array with the PHP vulnerable variables
     */
    function set_vulnerable_variables()
    {

    }

    /**
     * create the multi-dimensional associative array with the PHP vulnerable variables
     */
    function set_non_vulnerable_variables()
    {

    }

    /**
     * create the multi-dimensional associative array with the PHP output variables
     */
    function set_output_variables()
    {

    }

    /**
     * Parse blocks of non PHP code. Currentely nothing is done
     *
     * TODO check for other local PHP files by analyzing the hyperlinks
     * TODO javascript (hyperlinks, javascript variable usage and PHP variable usage inside javascript)
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
     * @param string $block_end_index with the end index of tokens the the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the end of the multi-dimensional array $files_tokens
     */
    function parse_non_php($file_name, $class_name, $function_name, $block_start_index)
    {
//$t = microtime(true);
//echo "<p>parse_non_php($file_name, $function_name, $block_start_index)</p>";
//$this->count_execution ++;
//$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_non_php($file_name, $function_name, $block_start_index)", 'parse_non_php($file_name, $function_name, $block_start_index)');

//Index of the start of non PHP code
        $block_end_index = $block_start_index;
        $token = $this->files->files_tokens[$file_name];
        do {
            $block_end_index++;
            if ($block_end_index >= count($token))
                break;
        } while (!(is_array($token[$block_end_index]) && ((T_OPEN_TAG === $token[$block_end_index][0]) || (T_OPEN_TAG_WITH_ECHO === $token[$block_end_index][0]))));
//$this->time_execution_of += microtime(true) - $t;
        return ($block_end_index);
    }

    /**
     * Parse for loop. Currentely it only calls the function $this->main_parser.
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
     * @param string $block_end_index with the end index of tokens the the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the end of the multi-dimensional array $files_tokens
     */
    function parse_for($file_name, $class_name, $function_name, $block_start_index)
    {
//$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_for($file_name, $function_name, $block_start_index)", 'parse_for($file_name, $function_name, $block_start_index)');

        $block_start_index++;
        if ('(' === $this->files->files_tokens[$file_name][$block_start_index]) {
            $block_end_index = $this->find_match($file_name, $block_start_index, '(');
        } else {
            $block_end_index = $this->end_of_php_line($file_name, $block_start_index);
        }

        $block_start_index++;
        $this->main_parser($file_name, $class_name, $function_name, $block_start_index, $block_end_index);

        return ($block_end_index);
    }

    /**
     * Parse foreach loop. Currentely it only calls the function $this->main_parser.
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
     * @param string $block_end_index with the end index of tokens the the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the end of the multi-dimensional array $files_tokens
     */
    function parse_foreach($file_name, $class_name, $function_name, $block_start_index)
    {
//$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_foreach($file_name, $function_name, $block_start_index)", 'parse_foreach($file_name, $function_name, $block_start_index)');

        $block_start_index++;
        if ('(' === $this->files->files_tokens[$file_name][$block_start_index]) {
            $block_end_index = $this->find_match($file_name, $block_start_index, '(');
            $block_start_index++;
        } else {
            $block_end_index = $this->end_of_php_line($file_name, $block_start_index);
        }


        for ($i = $block_start_index, $count = count($this->files->files_tokens[$file_name]); $i < $count - 1; $i++) {
            if ((is_array($this->files->files_tokens[$file_name][$i])) && (T_AS === $this->files->files_tokens[$file_name][$i][0])) {
                $block_as_index = $i;
                break;
            }
        }

        $expression = $this->parse_expression_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_as_index, null, null);

        if (is_null($expression[_PHPI_DEPENDENCIES_INDEX])) {
            $this->parse_variable_property($file_name, $class_name, $function_name, $block_as_index + 1);
        } else {
//skip '(' characters
            while ('(' === $this->files->files_tokens[$file_name][$block_start_index]) {
                $block_start_index++;
            }
            if (!is_array($this->files->files_tokens[$file_name][$block_start_index])) {
//TODO other characters that may exist
            }

            if (($this->is_variable($file_name, $block_start_index)) || ($this->is_property($file_name, $block_start_index))) {
                $v = $block_start_index;
//$v is passed by reference, NO
//$variable_before_as_name = $this->get_variable_property_complete_array_name($file_name, $v);
                $ra = $this->get_variable_property_complete_array_name($file_name, $v);
                $variable_before_as_name = $ra[0];
                $v = $ra[1];
            } elseif (($this->is_function($file_name, $block_start_index)) || ($this->is_method($file_name, $block_start_index))) {
//TODO
                $v = $block_start_index;
//$v is passed by reference
//$variable_before_as_name = $this->get_variable_property_complete_array_name($file_name, $v);
                $ra = $this->get_variable_property_complete_array_name($file_name, $v);
                $variable_before_as_name = $ra[0];
                $v = $ra[1];
            } else {
//TODO
            }

            $variable_before_as_index = $this->get_variable_index($file_name, $variable_before_as_name, $function_name);

            $this->parse_foreach_vulnerability($file_name, $class_name, $function_name, $block_as_index + 1, $block_end_index, $variable_before_as_index);
        }
        return $block_end_index;
    }

    /**
     * Verify if the variables in the multi-dimensional associative array $parser_variables depend on other variables
     * If any of the variables they depend is TAINTED then the variable is updated to be also TAINTED
     * The multi-dimensional associative array $parser_variables is updated accordingly
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $equal with the values '=' or 'as'
     * If it is an 'as' the assigned variable is the one in the right of the 'as'
     * If it is an '=' the assigned variable is the one in the left of the '=' sign
     * @param string $variable_before_as_index with the index of the variable in tokens of the multi-dimensional array $parser_variables
     *
     * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
     */
    function parse_foreach_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $variable_before_as_index)
    {

    }

    /**
     * Parse do...while loop. Currentely it only calls the function $this->main_parser.
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
     */
    function parse_do_while_do($file_name, $class_name, $function_name, $block_start_index)
    {
//$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_do_while_do($file_name, $function_name, $block_start_index)", 'parse_do_while_do($file_name, $function_name, $block_start_index)');

//do..while
        if (T_DO === $this->files->files_tokens[$file_name][$block_start_index][0]) {
//$block_end_index = $this->find_match($file_name, $block_start_index, '{'); // JF
            $block_end_index = $this->find_match($file_name, $block_start_index + 1, '{'); // PN
            $block_end_index = $this->end_of_php_line($file_name, $block_end_index);
//while
        } elseif (T_WHILE === $this->files->files_tokens[$file_name][$block_start_index][0]) {
//$block_end_index = $this->find_match($file_name, $block_start_index, '('); // JF
            $block_end_index = $this->find_match($file_name, $block_start_index + 1, '('); // PN
// XXXXXXXXXXX +1,add
//The alternate syntax
            if (':' === $this->files->files_tokens[$file_name][$block_end_index + 1]) {
                do {
                    $block_end_index++;
                } while (!(is_array($this->files->files_tokens[$file_name][$block_end_index]) && (T_ENDWHILE === $this->files->files_tokens[$file_name][$block_end_index][0])));
            }
        }

        $block_start_index++;
        $this->main_parser($file_name, $class_name, $function_name, $block_start_index, $block_end_index);

        return ($block_end_index);
    }

    /**
     * Parse if conditional statement. Currentely it only calls the function $this->main_parser.
     *
     * TODO parse differently the flow of the IF, ELSE, ELSEIF
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
     */
    function parse_if($file_name, $class_name, $function_name, $block_start_index)
    {
// $this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_if($file_name, $function_name, $block_start_index)", 'parse_if($file_name, $function_name, $block_start_index)');

        if ((T_IF === $this->files->files_tokens[$file_name][$block_start_index][0]) || (T_ELSEIF === $this->files->files_tokens[$file_name][$block_start_index][0])) {
// XXXXXXXXXXX +1,add
// $block_end_index = $this->find_match($file_name, $block_start_index, '('); /JF
            $block_end_index = $this->find_match($file_name, $block_start_index + 1, '('); // PN
        } // T_ELSE
        else {
            $block_end_index = $block_start_index;
        }

//The alternate syntax
        if (':' === $this->files->files_tokens[$file_name][$block_end_index + 1]) {
            do {
                $block_end_index++;
            } while (!(is_array($this->files->files_tokens[$file_name][$block_end_index]) && (T_ENDIF === $this->files->files_tokens[$file_name][$block_end_index][0])));

//if structure with {..}
        } elseif ('{' === $this->files->files_tokens[$file_name][$block_end_index + 1]) {
            $block_end_index = $this->find_match($file_name, $block_end_index + 1, '{');

//if structure with just one line of code
        } else {
            $block_end_index = $this->end_of_php_line($file_name, $block_end_index + 1);
        }
        $block_start_index++;

//        $ss = "<tr><th style='color:red;'>b:[$block_start_index, $block_end_index]</th></tr>";
//        echo $ss;
//        fprintf($this->text_file_stream, "%s", $ss);
//        fflush($this->text_file_stream);

        $this->main_parser($file_name, $class_name, $function_name, $block_start_index, $block_end_index);

//        $ss = "<tr><th style='color:red;'>a:[$block_start_index, $block_end_index]</th></tr>";
//        echo $ss;
//        fprintf($this->text_file_stream, "%s", $ss);
//        fflush($this->text_file_stream);
//$this->debug(' $block_end_index ' . $block_end_index . "<br />");
        if ($this->parser_debug2_flag)
            $this->debug2("parse_if - block_end_index($block_end_index)", 'parse_if - block_end_index($block_end_index');

        return ($block_end_index);
    }

    /**
     * Parse switch conditional statement. Currentely it only calls the function $this->main_parser.
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
     */
    function parse_switch($file_name, $class_name, $function_name, $block_start_index)
    {
//$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_switch($file_name, $function_name, $block_start_index)", 'parse_switch($file_name, $function_name, $block_start_index)');

//$block_end_index = $this->find_match($file_name, $block_start_index, '('); // JF
        $block_end_index = $this->find_match($file_name, $block_start_index + 1, '('); // PN
//The alternate syntax
        if (':' === $this->files->files_tokens[$file_name][$block_end_index + 1]) {
            do {
                $block_end_index++;
            } while (!(is_array($this->files->files_tokens[$file_name][$block_end_index]) && (T_ENDSWITCH === $this->files->files_tokens[$file_name][$block_end_index][0])));
        }

        $block_start_index++;
        $this->main_parser($file_name, $class_name, $function_name, $block_start_index, $block_end_index);

        return ($block_end_index);
    }

    /**
     * Parse include, include_once, require and require_once.
     * All of them are processed by calling the function $this->main_parser.
     *
     * TODO use include_paths()
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
     */
    function parse_include_require($file_name, $class_name, $function_name, $block_start_index)
    {
//$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_include_require($file_name, $function_name, $block_start_index)", 'parse_include_require($file_name, $function_name, $block_start_index)');

        $block_end_index = $this->end_of_php_line($file_name, $block_start_index);

//if there is an '(' after the include, include_once, require, require_once
        if ('(' === $this->files->files_tokens[$file_name][$block_start_index + 1]) {
            $file_name_include = $this->files->files_tokens[$file_name][$block_start_index + 2][1];
        } else {
            $file_name_include = $this->files->files_tokens[$file_name][$block_start_index + 1][1];
        }


//TODO use include_paths()
//Change PN
//$file_path = dirname($file_name) . DIRECTORY_SEPARATOR;
// get file name
        $file_path = dirname($this->files->files_tokens_names[$file_name]) . DIRECTORY_SEPARATOR;
// To.

        if (('"' === substr($file_name_include, 0, 1)) || ("'" === substr($file_name_include, 0, 1))) {
            $file_name_include = substr($file_name_include, 1, -1);
        }
        $file_name_include = $file_path . $file_name_include;
        $file_name_include = realpath(dirname($file_name_include)) . DIRECTORY_SEPARATOR . basename($file_name_include);

//echo "<hr />";
// Change PN
        foreach ($this->files->files_tokens_names as $key => $fln) {
//foreach ($this->files->files_tokens as $key => $token) {
// To.
//only parse the file if it is in the multi-dimensional array variable $files_tokens
//only analyze the included file if it has not been anayzed yet
//echo "<p>##################path:  $file_path <br/> file_name: $file_name  file_name_include: $file_name_include = $key / $fln</p>";
//Change PN
//if ($file_name_include === $key) {
            if ($file_name_include === $fln) {
// To.
// get the ...ONCE attribute
// get the INCLUDE.../REQUIRE... attribute
                $token = $this->files->files_tokens[$file_name][$block_start_index][0];
                if (T_INCLUDE_ONCE === $token) {
                    $once = 'true';
                    $include_require = 'include';
                } elseif (T_REQUIRE_ONCE === $token) {
                    $once = 'true';
                    $include_require = 'require';
                } elseif (T_INCLUDE === $token) {
                    $once = 'false';
                    $include_require = 'include';
                } elseif (T_REQUIRE === $token) {
                    $once = 'false';
                    $include_require = 'require';
                }

                $parse_again = false;
//store the include/require information int the multi-dimensional array variable $files_include_require
				if (is_array($this->files_include_require)) {
					$count_this_files_include_require = count($this->files_include_require);
				} else {
					$count_this_files_include_require = 0 ;
				}
                for ($i = 0, $count = $count_this_files_include_require; $i < $count; $i++) {
//check if the included/required file has already been included
                    if (($file_name_include === $this->files_include_require[$i]['include_require_file_name']) && ($include_require === $this->files_include_require[$i]['include_require'])) {
//the file has already been included/required once
                        $this->files_include_require[$i]['number_of_calls'] += 1;
//If is not a ...ONCE then it will be parsed every time
                        if ('false' === $once) {
                            $this->files_include_require[$i]['number_of_calls_executed'] += 1;
                            $parse_again = true;
                        }
                        break;
                    }
                }

//if this include/require has not yet been processed then add it to the multi-dimensional array variable $files_include_require
                if ($count === $i) {
                    $this->files_include_require[] = array(
                        'include_require_file_name' => $file_name_include,
                        'include_require' => $include_require,
                        'number_of_calls' => 1,
                        'number_of_calls_executed' => 1
                    );
                    $parse_again = true;
                }

//only parse the included/required file if it has not yet been parsed or it is not a ...ONCE file
                if (true === $parse_again) {
// Change PN
//$this->main_parser($file_name_include, null, null, null);
// Pass the number not the file name
                    $this->main_parser($key, null, null, null, null);
// To.
                }
                break; //do not need to continue searching
            }
        }
        return ($block_end_index);
    }

    /*
   *
   * return nul or int
   */

    function exists_class($file_name, $function_name)
    {
//
        for ($i = 0; $i < count($this->files_classes); $i++) {
            if (strtoupper($this->files_classes[$i][_PHPI_NAME]) === strtoupper($function_name)) {
                return $i;
            }
            echo $this->files_classes[$i][_PHPI_NAME] . ' - ' . $function_name . '<br>';
        }
        return null;
    }

    /**
     * parse functions
     *
     * TODO passing by reference
     *
     * note: You define a function with parameters, you call a function with arguments.
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
     */
    function parse_function_method($file_name, $class_name, $function_name, $block_start_index)
    {
// $class_name new in 2015-02-04
//$this->debug(sprintf("%s:%s:<b><span style='color:orange;'>%s</span></b> :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_function_method($file_name, $class_name, $function_name, $block_start_index)", 'parse_function_method($file_name, $class_name, $function_name, $block_start_index)');

        //echo "<p>OOP_parse_function_method ($function_name) " . $this->generate_code_from_tokens($this->files->files_tokens[$file_name], $block_start_index - 1, $block_start_index + 2) . '</p>';
// OOP
// If the function name is a class name then replace de class name with do name of the construct.
//    $i = $this->exists_class($file_name, $function_name);
//    if (is_int($i)) {
//      $construct_name = "__construct";
//      $function_name = $construct_name;
//      $block_start_index = 24;
//      echo $construct_name;
//    }

        $called_function_name = $this->get_function_method_name($file_name, $block_start_index);
        $block_start_index = $this->get_variable_property_function_method_last_index($file_name, $block_start_index);

        //$class_name = "Attendant";
        /*    $key = strtoupper("$file_name#$class_name#$called_function_name");
      $index_function = $this->files_functions_lookup[$key];
      print_r($this->files_functions[$index_function]);
     */
//calculate the end token of the function call
        if ('(' === $this->files->files_tokens[$file_name][$block_start_index + 1]) {
            $block_end_index = $this->find_match($file_name, $block_start_index + 1, '(');
        } else {
            $block_end_index = $this->end_of_php_line($file_name, $block_start_index);
        }
        $block_start_index++;

        $called_function_index = null;
// old
//get the index of the function in the multi-dimensional array $files_tokens
// search for the code of the PHP user defined function
//    for ($i = 0, $count = count($this->files_functions); $i < $count; $i++) {
//      //note: user defined PHP functions are not case sensitive
//      if (0 === strcasecmp($called_function_name, $this->files_functions[$i][_PHPI_NAME])) {
//        $called_function_index = $i;
//        // When the function is found in the the multi-dimensional array $this->files_functions
//        // there is no need to continue searching for more because there is only one function with the same name
//        break;
//      }
//      //there is no need for the else, because the function has to exist when arriving here
//    }
//old
// Change
        $called_function_name_upper = strtoupper("$file_name#$class_name#$called_function_name");
        if (isset($this->files_functions_lookup["$called_function_name_upper"]))
            $called_function_index = $this->files_functions_lookup["$called_function_name_upper"];
// To.
//    if ($called_function_index != $called_function_inde)
//      echo "$called_function_index != $called_function_inde <br>";

        $used_function_index = null;
        if (!is_null($called_function_index)) {
//found the code of the PHP user defined function
//so it is a PHP user defined function
//if it is a user defined function test to see if it is already being parsed
//should not parse functions with recursivity because it will never stop
//if the function is not already being parsed then parse it

            if ((!is_array($this->functions_stack)) || (!in_array($called_function_index, $this->functions_stack))) {
//push the function to the stack
                $this->functions_stack[] = $called_function_index;
                $used_function_index = $this->parse_user_defined_function_method_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $called_function_name, $called_function_index);
//pop the function from the stack
//unset the $files_functions_stack but keep the indexes untouched
                unset($this->functions_stack[count($this->functions_stack) - 1]);
//normalize the indexes
                $this->functions_stack = array_values($this->functions_stack);
            } else {
//the function is already being executed
            }
//all other functions that are not defined in the parsed PHP files, like echo, print, exit
        } else {
// fprintf($this->text_file_stream, "\t%s n","Other");
//fflush($this->text_file_stream);

            $used_function_index = $this->parse_other_function_method_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $called_function_name);
        }

//   return( $block_end_index);
        return (array($block_end_index, $called_function_name, $used_function_index));
    }

    /**
     * It is a user defined function so it is parsed
     *
     * note: You define a function with parameters, you call a function with arguments.
     *
     * @param string $file_name with the PHP file name of the calling function
     * @param string $function_name with the name of the function where the code is being executed, the calling function.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens of the calling function
     * @param string $block_end_index with the start index of tokens of the multi-dimensional array $files_tokens of the calling function
     * @param string $called_function_name with the name of the function, the called function
     */
// $class_name new in 2015-02-04
    // $called_class_name new in 2015-02-11

    function parse_user_defined_function_method_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $called_function_name, $called_function_index)
    {

    }

    /**
     * If the function is one of the output functions it is checked for tainted variables that could cause a vulnerability.
     *
     * note: You define a function with parameters, you call a function with arguments.
     *
     * @param string $file_name with the PHP file name of the calling function
     * @param string $function_name with the name of the function where the code is being executed, the calling function.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens of the calling function
     * @param string $block_end_index with the start index of tokens of the multi-dimensional array $files_tokens of the calling function
     * @param string $called_function_name with the name of the function, the called function
     */
    function parse_other_function_method_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $called_function_name)
    {

    }

    /**
     * parse return of functions
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
     */
    function parse_return($file_name, $class_name, $function_name, $block_start_index)
    {
//$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_return($file_name, $function_name, $block_start_index)", 'parse_return($file_name, $function_name, $block_start_index)');

//calculate the end token of the return statement
        if ('(' === $this->files->files_tokens[$file_name][$block_start_index + 1]) {
//$block_end_index = $this->find_match($file_name, $block_start_index, '('); //JF
// XXXXXXXXXXX +1,add
            $block_end_index = $this->find_match($file_name, $block_start_index + 1, '('); // PN
        } else {
            $block_end_index = $this->end_of_php_line($file_name, $block_start_index);
        }

        $block_start_index++;

        $this->parse_return_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index);

        return ($block_end_index);
    }

    /**
     * Add a variable with the name of the function with the return value if there is no older one.
     * If the function had already a return value tainted, then do not add a new variable.
     * If the function had already a return value untainted and the new variable is tainted, then add a new variable and delete the old one.
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     */
    function parse_return_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index)
    {

    }

    /**
     * parse the '=' token
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
     *
     * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
     */
    function parse_equal($file_name, $class_name, $function_name, $block_start_index)
    {
//$this->debug(sprintf("%s:%s:<b><span style='color:magenta;'>%s</span></b> :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_equal($file_name, $function_name, $block_start_index)", 'parse_equal($file_name, $function_name, $block_start_index)');

//find the variable that is assigned something by searching backwards in the multi-dimensional array $files_tokens
        $variable_before_equal_name = null;
        $i = $block_start_index;

//get the name of the assigned variable or method proterty (the one before the '=' sign)
        do {
            if ((is_array($this->files->files_tokens[$file_name][$i])) && (($this->is_variable($file_name, $i)) || ($this->is_property($file_name, $i)))) {
                $v = $i;
//$v is passed by reference
//$variable_before_equal_name = $this->get_variable_property_complete_array_name($file_name, $v);
                $ra = $this->get_variable_property_complete_array_name($file_name, $v);
                $variable_before_equal_name = $ra[0];
                $v = $ra[1];
            }
            $i--;
        } while ((0 <= $i) && (is_null($variable_before_equal_name)));

        $variable_before_equal_index = $this->get_variable_index($file_name, $variable_before_equal_name, $function_name);
        $block_end_index = $this->end_of_php_line($file_name, $block_start_index);

        $block_start_index++;
        $this->parse_equal_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $variable_before_equal_index);

        return $block_end_index;
    }

    /**
     * Verify if the variables in the multi-dimensional associative array $parser_variables depend on other variables
     * If any of the variables they depend is TAINTED then the variable is updated to be also TAINTED
     * The multi-dimensional associative array $parser_variables is updated accordingly
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $equal with the values '=' or 'as'
     * If it is an 'as' the assigned variable is the one in the right of the 'as'
     * If it is an '=' the assigned variable is the one in the left of the '=' sign
     * @param string $variable_before_equal_index with the index of the variable in tokens of the multi-dimensional array $parser_variables
     *
     * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
     */
    function parse_equal_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $variable_before_equal_index)
    {

    }

    /**
     * Parse variables and object properties
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
     *
     * @return int with the index of multi-dimensional associative array $files_tokens with the end of the variable
     */
    function parse_variable_property($file_name, $class_name, $function_name, $block_start_index)
    {
//$this->debug(sprintf("%s:%s:<span style='color:brown;'>%s</span> :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag)
            $this->debug2("parse_variable_property($file_name, $function_name, $block_start_index)", 'parse_variable_property($file_name, $function_name, $block_start_index)');


        $code_type = PHP_CODE;
        $function_name = $this->find_function_name_of_code($file_name, $block_start_index);

        if (T_GLOBAL === $this->files->files_tokens[$file_name][$block_start_index][0]) {
            $variable_scope = 'global';
            $block_start_index++;
        } else {
            $variable_scope = 'local';
        }

//skip constant definitions
        if (T_CONST === $this->files->files_tokens[$file_name][$block_start_index][0]) {
            $block_start_index++;
            $block_end_index = $this->end_of_php_line($file_name, $block_start_index);
            return ($block_end_index);
        }

        $block_end_index = $block_start_index;
//$block_end_index is passed by reference
//$variable_name = $this->get_variable_property_complete_array_name($file_name, $block_end_index);
        $ra = $this->get_variable_property_complete_array_name($file_name, $block_end_index);
        $variable_name = $ra[0];
        $block_end_index = $ra[1];

        if ($block_end_index > $block_start_index + 1) {
//If there is a function call inside the variable definition it should be executed
            $this->main_parser($file_name, $class_name, $function_name, $block_start_index + 1, $block_end_index);
        }

        $this->parse_variable_property_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $variable_name, $variable_scope, $code_type);

        return ($block_end_index);
    }

    /**
     * Extract the variable information from the multi-dimensional array $files_tokens
     * and store it in the multi-dimensional associative array $parser_variables
     * Make a distinction between regular and input variables
     * Taint the input variables
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code is being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $variable_name with the name of the variable
     * @param string $variable_scope with the scope of the variable: local or global
     * @param string $code_type with the type of PHP code: php code or non php code
     *
     * @return int with the index of multi-dimensional associative array $files_tokens with the end of the variable
     */
    function parse_variable_property_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $variable_name, $variable_scope, $code_type)
    {

    }

    /**
     * Parse unset
     * The variable is created
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * If this argument is null it is assumed as the begining of the multi-dimensional array $files_tokens
     */
    function parse_unset($file_name, $class_name, $function_name, $block_start_index)
    {
//$this->debug(sprintf("%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize(func_get_args())) . '<br />');

        if ($this->parser_debug2_flag) {
            $this->debug2("parse_unset($file_name, $function_name, $block_start_index)", 'parse_unset($file_name, $function_name, $block_start_index)');
        }

        if ('(' === $this->files->files_tokens[$file_name][$block_start_index + 1]) {
//$block_end_index = $this->find_match($file_name, $block_start_index, '('); // JF
// XXXXXXXXXXX +1,add
            $block_end_index = $this->find_match($file_name, $block_start_index + 1, '(');  // PN
            $block_start_index++;
        } else {
            $block_end_index = $this->end_of_php_line($file_name, $block_start_index);
        }

        $i = $this->parse_variable_property($file_name, $class_name, $function_name, $block_start_index + 1);

        $v = $block_start_index + 1;
//$v is passed by reference
//$variable_name = $this->get_variable_property_complete_array_name($file_name, $v);
        $ra = $this->get_variable_property_complete_array_name($file_name, $v);
        $variable_name = $ra[0];
        $v = $ra[1];

        $variable_index = $this->get_variable_index($file_name, $variable_name, $function_name);
        $this->parse_unset_vulnerability($block_end_index, $variable_index);
        return ($block_end_index);
    }

    /**
     * Parse unset. The variable becomes untainited
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $block_end_index with the end index of tokens the the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $variable_index with the index of tokens the the multi-dimensional array $parser_variables
     */
    function parse_unset_vulnerability($block_end_index, $variable_index)
    {

    }

    /**
     * Find the start of the PHP line of code.
     * the start of PHP line is calculated by searching backward for the first occurrence of either ';', '}', '{', T_OPEN_TAG, T_OPEN_TAG_WITH_ECHO
     *
     * TODO search for a better algoritm
     *
     * @param int $pointer with the index of the multi-dimensional array $files_tokens
     * @return int with the index of multi-dimensional associative array $files_tokens that corresponds to the start of the PHP line of code
     */
    function start_of_php_line($file_name, $pointer)
    {
//$time_start = microtime(true);
// Change PN
        if (isset($this->start_of_php_line_lookup[$file_name][$pointer])) {
//$this->count_find_match ++;
            return $this->start_of_php_line_lookup[$file_name][$pointer];
        }
// To.
// The value isn't tabled, evaluate it and add to the table
        $index = $pointer;

        $is_start_of_line = false;
        do {
//search for the first occurrence of either ';', '}', '{'
            if ((';' === $this->files->files_tokens[$file_name][$pointer]) || ('}' === $this->files->files_tokens[$file_name][$pointer]) || ('{' === $this->files->files_tokens[$file_name][$pointer])) {
                $is_start_of_line = true;

//search for the first occurrence of either T_OPEN_TAG, T_OPEN_TAG_WITH_ECHO
            } elseif
            ((T_OPEN_TAG === $this->files->files_tokens[$file_name][$pointer][0]) || (T_OPEN_TAG_WITH_ECHO === $this->files->files_tokens[$file_name][$pointer][0])
            ) {
                $is_start_of_line = true;

//keep searching if nothing was found
            } elseif (false === $is_start_of_line) {
                $pointer--;
            }

//keep searching if nothing was found and it is not the start of the PHP file
        } while ((false === $is_start_of_line) && (0 < $pointer));

//$this->time_execution_of += microtime(true) - $time_start;
//table the value
        $this->start_of_php_line_lookup[$file_name][$index] = $pointer;
        return $pointer;
    }

    /**
     * Find the end of the PHP line of code
     * the end of PHP line is calculated by searching forward for the first occurrence of either ';', '}', '{', T_CLOSE_TAG
     *
     * TODO search for a better algoritm
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param int $pointer with the index of the multi-dimensional array $files_tokens
     *
     * @return int with the index of multi-dimensional associative array $iles_tokens that corresponds to the end of the PHP line of code
     */
    function end_of_php_line($file_name, $pointer)
    {
//$time_start = microtime(true);
// Change PN
        if (isset($this->end_of_php_line_lookup[$file_name][$pointer])) {
//$this->count_find_match ++;
            return $this->end_of_php_line_lookup[$file_name][$pointer];
        }
// To.
// The value isn't tabled, evaluate it and add to the table
        $index = $pointer;

        $is_end_of_line = false;
        $count = count($this->files->files_tokens[$file_name]) - 1;

        do {
//search for the first occurrence of either ';', '}', '{'
            if ((';' === $this->files->files_tokens[$file_name][$pointer]) || ('}' === $this->files->files_tokens[$file_name][$pointer]) || ('{' === $this->files->files_tokens[$file_name][$pointer])) {
                $is_end_of_line = true;
            } elseif (T_CLOSE_TAG === $this->files->files_tokens[$file_name][$pointer][0]) {  //search for the first occurrence of either T_CLOSE_TAG
                $is_end_of_line = true;
            } elseif (false === $is_end_of_line) {                                              //keep searching if nothing was found
                $pointer++;
            }

//keep searching if nothing was found and it is not the end of the PHP file
        } while (($is_end_of_line === false) && ($count - 1 > $pointer));

//if after the ';' it is the end of the PHP block then the end of the line is the end of the PHP block
        if ((';' === $this->files->files_tokens[$file_name][$pointer]) && (T_CLOSE_TAG === $this->files->files_tokens[$file_name][$pointer + 1][0])) {
            $pointer++;
        }

//$this->time_execution_of += microtime(true) - $time_start;
// table the value
        $this->end_of_php_line_lookup[$file_name][$index] = $pointer;
        return $pointer;
    }

//  function find_match_original($file_name, $block_start_index, $open_token) {
////calculate the matching close token
//
//      echo "<p>find_match_original($file_name, $block_start_index, $open_token)</p>";
//        switch ($open_token) {
//            case '(':
//                $close_token = ')';
//                break;
//            case '{':
//                $close_token = '}';
//                break;
//            case '[':
//                $close_token = ']';
//                break;
//
//            default:
//                return null;
//                break;
//        }
//
//        $count_open = 0;
//        $count_close = 0;
//
////search for the match by taking into account the number of pairs of matching tokens
//        $ISA = $this->files->files_tokens_is_array[$file_name];
//        for ($i = $block_start_index, $count = count($this->files->files_tokens[$file_name]); $i < $count; $i++) {
//            $t = $this->files->files_tokens[$file_name][$i];
//            if (( $open_token === $t ) || (($ISA[$i]) && ('{' === $open_token) && (T_CURLY_OPEN === $t[0]) )) {
//                //if (( $open_token === $this->files->files_tokens[$file_name][$i] ) || ((is_array($this->files->files_tokens[$file_name][$i])) && ('{' === $open_token) && (T_CURLY_OPEN === $this->files->files_tokens[$file_name][$i][0]) )) {
//                $count_open++;
//                //} elseif ($close_token === $this->files->files_tokens[$file_name][$i]) {
//            } elseif ($close_token === $t) {
//                $count_close++;
////end searching when the number of pairs of matching tokens is 0
////this condition is tested only when a close token is found
//                if (0 === $count_open - $count_close) {
//                    break;
//                }
//            }
//        }
//
////$i contains the index of the matching close token (or the end of the PHP file) in the multi-dimensional associative array $files_tokens
//        return $i;
//    }
    /**
     * Search for the matching end token of the open token passed as an argument.
     * The search ends when the matching token is found
     * There is a guarantee that a pair of tokens is found (or the end of the PHP file)
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $open_token with the open token, that can be a '(' or a '{'
     *
     * @return int with the index of the matching close token in the multi-dimensional associative array $files_tokens
     */
    function find_match($file_name, $block_start_index, $open_token)
    {

        if ($open_token === '(') {
            $close_token = ')';
        } elseif ($open_token === '{') {
            $close_token = '}';
        } elseif ($open_token === '[') {
            $close_token = ']';
        } else {
            $this->echo_h1("find_match($file_name, $block_start_index, $open_token)", 'red');
            return null;
        }
        $key = "$file_name#$block_start_index#$open_token";
        if (isset($this->files->find_match_array["$key"])) {
//$this->count_find_match ++;
            return $this->files->find_match_array["$key"];
        }

        $count_open = 0;
        $count_close = 0;

//search for the match by taking into account the number of pairs of matching tokens
        $ISA = $this->files->files_tokens_is_array[$file_name];
        for ($i = $block_start_index, $count = count($this->files->files_tokens[$file_name]); $i < $count; $i++) {
            $t = $this->files->files_tokens[$file_name][$i];
            if (($open_token === $t) || (($ISA[$i]) && ('{' === $open_token) && (T_CURLY_OPEN === $t[0]))) {
//if (( $open_token === $this->files->files_tokens[$file_name][$i] ) || ((is_array($this->files->files_tokens[$file_name][$i])) && ('{' === $open_token) && (T_CURLY_OPEN === $this->files->files_tokens[$file_name][$i][0]) )) {
                $count_open++;
//} elseif ($close_token === $this->files->files_tokens[$file_name][$i]) {
            } elseif ($close_token === $t) {
                $count_close++;
//end searching when the number of pairs of matching tokens is 0
//this condition is tested only when a close token is found
                if (0 === $count_open - $count_close) {
                    break;
                }
            }
        }
//echo "<p>$key $i</p>";
        $this->files->find_match_array["$key"] = $i;
//$i contains the index of the matching close token (or the end of the PHP file) in the multi-dimensional associative array $files_tokens
        return $i;
    }

    /**
     * Search for the next token passed as an argument in the multi-dimensional associative array $files_tokens.
     * If in between there are '(' '{' " ' it resumes the search only after the matching ')' '}' " '
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $token with the token
     *
     * @return int with the index of the end token in the multi-dimensional associative array $files_tokens
     */
    function find_token($file_name, $block_start_index, $token)
    {
//$time_start = microtime(true);
// Change PN
        if (isset($this->find_token_lookup[$file_name][$block_start_index][$token])) {
            return $this->find_token_lookup[$file_name][$block_start_index][$token];
        }
// To.
// The value isn't tabled, evaluate it and add to the table
//search for the end of the function
        for ($i = $block_start_index, $count = count($this->files->files_tokens[$file_name]); $i < $count; $i++) {
            if ($this->files->files_tokens[$file_name][$i] === $token) {
                break;
            }
//skip if a pair of (..) or {..} is found
            if (('(' === $this->files->files_tokens[$file_name][$i]) || ('{' === $this->files->files_tokens[$file_name][$i]) || ((is_array($this->files->files_tokens[$file_name][$i])) && (T_CURLY_OPEN === $this->files->files_tokens[$file_name][$i][0]))) {
                if (((is_array($this->files->files_tokens[$file_name][$i])) && (T_CURLY_OPEN === $this->files->files_tokens[$file_name][$i][0]))) {
                    $i = $this->find_match($file_name, $i, '{');
                } else {
                    $i = $this->find_match($file_name, $i, $this->files->files_tokens[$file_name][$i]);
                }
            }
        }
// table the value
        $this->find_token_lookup[$file_name][$block_start_index][$token] = $i;
//$i contains the index of the token (or the end of the PHP file) in the multi-dimensional associative array $files_tokens
        return $i;
    }

    /**
     * Search for the function .
     * If in between there are '(' '{' " ' it resumes the search only after the matching ')' '}' " '
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $token with the token
     *
     * @return int with the index of the end token in the multi-dimensional associative array $files_tokens
     */
    function find_previous_containing_function_from_index($file_name, $block_index)
    {
// Change PN
        if (isset($this->find_previous_containing_function_from_index_lookup[$file_name][$block_index])) {
            return $this->find_previous_containing_function_from_index_lookup[$file_name][$block_index];
        }
// To.
// The value isn't tabled, evaluate it and add to the table
        $function_name = null;
        $token = $this->files->files_tokens[$file_name];
        for ($i = 0; $i < $block_index; $i++) {

            if ((T_ECHO === $token[$i][0]) || (T_PRINT === $token[$i][0]) || (T_EXIT === $token[$i][0]) || (T_INT_CAST === $token[$i][0]) || (T_DOUBLE_CAST === $token[$i][0]) || (T_STRING_CAST === $token[$i][0]) || (T_ARRAY_CAST === $token[$i][0]) || (T_OBJECT_CAST === $token[$i][0]) || (T_BOOL_CAST === $token[$i][0]) || (T_UNSET_CAST === $token[$i][0]) || ($this->is_function($file_name, $i)) || ($this->is_method($file_name, $i))) {
//calculate the end token of the function call
                $called_function_name = $this->get_function_method_name($file_name, $i);
                $i = $this->get_variable_property_function_method_last_index($file_name, $i);

                if ('(' === $this->files->files_tokens[$file_name][$i + 1]) {
                    $function_end_index = $this->find_match($file_name, $i + 1, '(');
                } else {
                    $function_end_index = $this->end_of_php_line($file_name, $i);
                }
                if (($block_index >= $i) && ($block_index <= $function_end_index)) {
                    $function_name = $called_function_name;
                }
                if ($this->is_method($file_name, $i)) {
//it is an object user defined function
                    $i += 2;
                }
            }
        }
// table the value
        $this->find_previous_containing_function_from_index_lookup[$file_name][$block_index] = $function_name;
//$i contains the index of the token (or the end of the PHP file) in the multi-dimensional associative array $files_tokens
        return $function_name;
    }

    /**
     * Search for the name of the function from which the code in the multi-dimensional associative array $files_tokens belongs to.
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
     *
     * @return string with the name of the function or the string 'function' in the case the code is from outside any function
     */
    function find_function_name_of_code($file_name, $file_index)
    {
// Change PN
        if (isset($this->find_function_name_of_code_lookup[$file_name][$file_index])) {
//$this->count_find_match ++;
            return $this->find_function_name_of_code_lookup[$file_name][$file_index];
        }
// To.
// The value isn't tabled, evaluate it and add to the table
//search for user defined functions in the multi-dimensional associative array $files_tokens
        $function_name = 'function';
        if (!empty($this->files_functions)) {
            foreach ($this->files_functions as $key => $value) {
                if (($value[_PHPI_FILE] === $file_name) && ($value[_PHPI_START_INDEX] <= $file_index) && ($value[_PHPI_END_INDEX] >= $file_index)) {
                    $function_name = $value[_PHPI_NAME];
//do not return here, because there may be a function definition inside a function definition
                }
            }
        }
//table the value
        $this->find_function_name_of_code_lookup[$file_name][$file_index] = $function_name;
        return $function_name;
    }

    /**
     * return true if the function is a php user defined function and false otherwise
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function that is going to be searched
     *
     * @return boolean with true if the token is a php user defined function and false otherwise
     */
    function is_user_defined_function($file_name, $function_name)
    {
// Change PN
        if (isset($this->is_user_defined_function_lookup[$file_name][$function_name])) {
//$this->count_find_match ++;
            return $this->is_user_defined_function_lookup[$file_name][$function_name];
        }
// To.
// The value isn't tabled, evaluate it and add to the table
//search for user defined functions in the multi-dimensional associative array $files_tokens
        if (!empty($this->files_functions)) {
            foreach ($this->files_functions as $key => $value) {
                if (($value[_PHPI_FILE] === $file_name) && ($value[_PHPI_NAME] === $function_name)) {
//table the value
                    $this->files->is_user_defined_function_lookup[$file_name][$function_name] = true;
                    return true;
                }
            }
        }
//table the value
        $this->is_user_defined_function_lookup[$file_name][$function_name] = false;
        return false;
    }

    /**
     * return true if the token is a php variable and false otherwise
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
     *
     * @return boolean with true if the token is a php variable and false otherwise
     */
    function is_variable($file_name, $file_index)
    {
        if ('variable' === $this->check_variable_function_property_method($file_name, $file_index)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * return true if the token is an object property and false otherwise
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
     *
     * @return boolean with true if the token is an object property and false otherwise
     */
    function is_property($file_name, $file_index)
    {
        if ('property' === $this->check_variable_function_property_method($file_name, $file_index)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * return true if the token is a php user defined function and false otherwise
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
     *
     * @return boolean with true if the token is a php user defined function and false otherwise
     */
    function is_function($file_name, $file_index)
    {
        if ('function' === $this->check_variable_function_property_method($file_name, $file_index)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * return true if the token is an object method and false otherwise
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
     *
     * @return boolean with true if the token is an object method and false otherwise
     */
    function is_method($file_name, $file_index)
    {
        if ('method' === $this->check_variable_function_property_method($file_name, $file_index)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * check if the token is a php variable, an object property, a php user defined function or an object method
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
     *
     * @return string with 'variable', 'property', 'function' or 'method'
     * if the token is respectively a php variable, an object property, a php user defined function or an object method and null otherwise
     */
    function check_variable_function_property_method($file_name, $file_index)
    {

// Change PN
        if (isset($this->check_variable_function_property_method_lookup[$file_name][$file_index])) {
//$this->count_find_match ++;
            return $this->check_variable_function_property_method_lookup[$file_name][$file_index];
        }
// To.
// The value isn't tabled, evaluate it and add to the table
//    $t = microtime(true);
//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
        if ($file_index >= 0) {
            $token = $this->files->files_tokens[$file_name];

//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
            if (($file_index >= 2) && ((T_OBJECT_OPERATOR === $token[$file_index - 1][0]) || (T_DOUBLE_COLON === $token[$file_index - 1][0]))) {
                $file_index = $file_index - 2;
            }

            if ((T_VARIABLE === $token[$file_index][0]) || (T_STRING === $token[$file_index][0]) || (T_ECHO === $token[$file_index][0]) || (T_PRINT === $token[$file_index][0]) || (T_EXIT === $token[$file_index][0]) || (T_INT_CAST === $token[$file_index][0]) || (T_DOUBLE_CAST === $token[$file_index][0]) || (T_STRING_CAST === $token[$file_index][0]) || (T_ARRAY_CAST === $token[$file_index][0]) || (T_OBJECT_CAST === $token[$file_index][0]) || (T_BOOL_CAST === $token[$file_index][0]) || (T_UNSET_CAST === $token[$file_index][0])
            ) {
                $name = $token[$file_index][1];

                while ((T_OBJECT_OPERATOR === $token[$file_index + 1][0]) || (T_DOUBLE_COLON === $token[$file_index + 1][0])) {

//for dynamically defined variable name, the name of the variable is the constant part only
//TODO improvement in this code
                    if ('{' === $token[$file_index + 2]) {
                        $file_index = $this->find_match($file_name, $file_index + 2, '{');
                        break;
                    }

                    $name = $name . $token[$file_index + 1][1] . $token[$file_index + 2][1];
                    $file_index += 2;
                }
                if ((T_OBJECT_OPERATOR === $token[$file_index - 1][0]) || (T_DOUBLE_COLON === $token[$file_index - 1][0])) {

//method
                    if ('(' === $token[$file_index + 1][0]) {
                        $this->check_variable_function_property_method_lookup[$file_name][$file_index] = 'method';
                        return 'method';
//$this->time_execution_of += microtime(true) - $t;
//property
                    } else {
//$this->time_execution_of += microtime(true) - $t;
                        $this->check_variable_function_property_method_lookup[$file_name][$file_index] = 'property';
                        return 'property';
                    }
                } else {

//variable
                    if ((T_VARIABLE === $token[$file_index][0]) && ('(' != $token[$file_index + 1][0])) {
//$this->time_execution_of += microtime(true) - $t;
                        $this->check_variable_function_property_method_lookup[$file_name][$file_index] = 'variable';
                        return 'variable';
//function
                    } elseif ((T_STRING === $token[$file_index][0]) && ('(' === $token[$file_index + 1][0])) {
//$this->time_execution_of += microtime(true) - $t;
                        $this->check_variable_function_property_method_lookup[$file_name][$file_index] = 'function';
                        return 'function';
//function
                    } elseif ((T_ECHO === $token[$file_index][0]) || (T_PRINT === $token[$file_index][0]) || (T_EXIT === $token[$file_index][0]) || (T_INT_CAST === $token[$file_index][0]) || (T_DOUBLE_CAST === $token[$file_index][0]) || (T_STRING_CAST === $token[$file_index][0]) || (T_ARRAY_CAST === $token[$file_index][0]) || (T_OBJECT_CAST === $token[$file_index][0]) || (T_BOOL_CAST === $token[$file_index][0]) || (T_UNSET_CAST === $token[$file_index][0])
                    ) {
//$this->time_execution_of += microtime(true) - $t;
                        $this->check_variable_function_property_method_lookup[$file_name][$file_index] = 'function';
                        return 'function';
                    } else {
//$this->time_execution_of += microtime(true) - $t;
                        $this->check_variable_function_property_method_lookup[$file_name][$file_index] = null;
                        return null;
                    }
                }
//$this->time_execution_of += microtime(true) - $t;} else {
                $this->check_variable_function_property_method_lookup[$file_name][$file_index] = null;
                return null;
            }
        } else {
            $this->check_variable_function_property_method_lookup[$file_name][$file_index] = null;
//$this->time_execution_of += microtime(true) - $t;
            return null;
        }
    }

    function get_variable_property_function_method_last_index($file_name, $file_index)
    {
        if ('&' === $this->files->files_tokens[$file_name][$file_index]) {
            $file_index++;
            //echo "$file_index " . $this->files->files_tokens[$file_name][$file_index][0];
        }
        // OOP_PM

        $count = count($this->files->files_tokens[$file_name]);
        if (($file_index < $count - 3) && ((T_OBJECT_OPERATOR === $this->files->files_tokens[$file_name][$file_index][0]) || (T_DOUBLE_COLON === $this->files->files_tokens[$file_name][$file_index][0]))) {
            $file_index = $file_index + 1;
        }
        // change from original on 2015-02-11: to lead with &
        while ((T_OBJECT_OPERATOR === $this->files->files_tokens[$file_name][$file_index + 1][0])
            || (T_DOUBLE_COLON === $this->files->files_tokens[$file_name][$file_index + 1][0])) {
            $file_index += 2;
        }
        return $file_index;
    }

    /**
     * get the name of the php user defined function or an object method by parsing the multi-dimensional associative array $files_tokens
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
     *
     * @return string with the name of the php user defined function or the object method or 'variable' or 'property' or null
     */
    function get_function_method_name($file_name, $file_index)
    {

// Change PN
        if (isset($this->get_function_method_name_lookup[$file_name][$file_index])) {
//$this->count_find_match ++;
            return $this->get_function_method_name_lookup[$file_name][$file_index];
        }
// To.
// The value isn't tabled, evaluate it and add to the table
//
//$this->count_execution++;
//$t = microtime(true);
        $name = null;

//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
        if ($file_index >= 0) {
            $token = $this->files->files_tokens[$file_name];

//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
            if (($file_index >= 2) && ((T_OBJECT_OPERATOR === $token[$file_index - 1][0]) || (T_DOUBLE_COLON === $token[$file_index - 1][0]))) {
                $file_index = $file_index - 2;
            }

            if ((T_VARIABLE === $token[$file_index][0]) || (T_STRING === $token[$file_index][0]) || (T_ECHO === $token[$file_index][0]) || (T_PRINT === $token[$file_index][0]) || (T_EXIT === $token[$file_index][0]) || (T_INT_CAST === $token[$file_index][0]) || (T_DOUBLE_CAST === $token[$file_index][0]) || (T_STRING_CAST === $token[$file_index][0]) || (T_ARRAY_CAST === $token[$file_index][0]) || (T_OBJECT_CAST === $token[$file_index][0]) || (T_BOOL_CAST === $token[$file_index][0]) || (T_UNSET_CAST === $token[$file_index][0])
            ) {

                $name = $token[$file_index][1];
                while ((T_OBJECT_OPERATOR === $token[$file_index + 1][0]) || (T_DOUBLE_COLON === $token[$file_index + 1][0])) {


//for dynamically defined variable name, the name of the variable is the constant part only
//TODO improvement in this code
                    if ('{' === $token[$file_index + 2]) {
                        $file_index = $this->find_match($file_name, $file_index + 2, '{');
//            $function_name = $this->get_function_method_name( $file_name, $file_index );
//            $expression = $this->parse_expression_vulnerability( $file_name, $function_name, $file_index, $file_end_index, null, null );
                        break;
                    }

                    $name = $name . $token[$file_index + 1][1] . $token[$file_index + 2][1];
                    $file_index += 2;
                }
                if ((T_OBJECT_OPERATOR === $token[$file_index - 1][0]) || (T_DOUBLE_COLON === $token[$file_index - 1][0])) {

//method
                    if ('(' === $token[$file_index + 1][0]) {
                        $this->get_function_method_name_lookup[$file_name][$file_index] = $name;
                        return $name;
//property
                    } else {
                        $this->get_function_method_name_lookup[$file_name][$file_index] = $name;
                        return $name;
                    }
                } else {

//variable
                    if ((T_VARIABLE === $token[$file_index][0]) && ('(' != $token[$file_index + 1][0])) {
                        $this->get_function_method_name_lookup[$file_name][$file_index] = $name;
                        return $name;

//function
                    } elseif ((T_STRING === $token[$file_index][0]) && ('(' === $token[$file_index + 1][0])) {
                        $this->get_function_method_name_lookup[$file_name][$file_index] = $name;
                        return $name;

//function
                    } elseif ((T_ECHO === $token[$file_index][0]) || (T_PRINT === $token[$file_index][0]) || (T_EXIT === $token[$file_index][0]) || (T_INT_CAST === $token[$file_index][0]) || (T_DOUBLE_CAST === $token[$file_index][0]) || (T_STRING_CAST === $token[$file_index][0]) || (T_ARRAY_CAST === $token[$file_index][0]) || (T_OBJECT_CAST === $token[$file_index][0]) || (T_BOOL_CAST === $token[$file_index][0]) || (T_UNSET_CAST === $token[$file_index][0])
                    ) {

//strip all whitespace from name, like replacing ( int ) with (int)
                        $name = preg_replace('/\s+/', '', $name);
                        $this->get_function_method_name_lookup[$file_name][$file_index] = $name;
                        return $name;
                    } else {
                        $this->get_function_method_name_lookup[$file_name][$file_index] = null;
                        return null;
                    }
                }
            } else {
                $this->get_function_method_name_lookup[$file_name][$file_index] = null;
                return null;
            }
        } else {
            $this->get_function_method_name_lookup[$file_name][$file_index] = null;
            return null;
        }
    }

    /**
     * get the name of the php variable or an object property by parsing the multi-dimensional associative array $files_tokens
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $file_index with the index of the token of the multi-dimensional array $files_tokens that is going to be parsed
     *
     * @return string with the name of the php variable or the object property or 'function' or 'method' or null
     */
    function get_variable_property_name($file_name, $file_index)
    {
//$this->count_execution++;
//$t = microtime(true);
// Change PN, update  $file_index
        if (isset($this->get_variable_property_name_lookup[$file_name][$file_index])) {
//$this->count_find_match ++;
//$file_index = $this->get_variable_property_complete_array_name_lookup_file_index[$file_name][$file_index];
            return $this->get_variable_property_name_lookup[$file_name][$file_index];
        }
// To.
// The value isn't tabled, evaluate it and add to the table
        $file_index_ant = $file_index;

        $name = null;

//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
        if ($file_index >= 0) {
            $token = $this->files->files_tokens[$file_name];

//test if the $file_index is at the start of a php variable, an object property, a php user defined function or an object method
            while (($file_index >= 2) && ((T_OBJECT_OPERATOR === $token[$file_index - 1][0]) || (T_DOUBLE_COLON === $token[$file_index - 1][0]))) {
                $file_index = $file_index - 2;
            }


            if ((T_VARIABLE === $token[$file_index][0]) || (T_STRING === $token[$file_index][0]) || (T_ECHO === $token[$file_index][0]) || (T_PRINT === $token[$file_index][0]) || (T_EXIT === $token[$file_index][0]) || (T_INT_CAST === $token[$file_index][0]) || (T_DOUBLE_CAST === $token[$file_index][0]) || (T_STRING_CAST === $token[$file_index][0]) || (T_ARRAY_CAST === $token[$file_index][0]) || (T_OBJECT_CAST === $token[$file_index][0]) || (T_BOOL_CAST === $token[$file_index][0]) || (T_UNSET_CAST === $token[$file_index][0])
            ) {

                $name = $token[$file_index][1];
                while ((T_OBJECT_OPERATOR === $token[$file_index + 1][0]) || (T_DOUBLE_COLON === $token[$file_index + 1][0])) {


//for dynamically defined variable name, the name of the variable is the constant part only
//TODO improvement in this code
                    if ('{' === $token[$file_index + 2]) {
                        $file_index = $this->find_match($file_name, $file_index + 2, '{');
//            $function_name = $this->get_function_method_name( $file_name, $file_index );
//            $expression = $this->parse_expression_vulnerability( $file_name, $function_name, $file_index, $file_end_index, null, null );
                        break;
                    }

                    $name = $name . $token[$file_index + 1][1] . $token[$file_index + 2][1];
                    $file_index += 2;
                }
                if ((T_OBJECT_OPERATOR === $token[$file_index - 1][0]) || (T_DOUBLE_COLON === $token[$file_index - 1][0])) {

//method
                    if ('(' === $token[$file_index + 1][0]) {
                        $this->get_variable_property_name_lookup[$file_name][$file_index] = 'function';
                        return 'function';
//property
                    } else {
                        $this->get_variable_property_name_lookup[$file_name][$file_index] = $name;
                        return $name;
                    }
                } else {

//variable
                    if ((T_VARIABLE === $token[$file_index][0]) && ('(' != $token[$file_index + 1][0])) {
                        $this->get_variable_property_name_lookup[$file_name][$file_index] = $name;
                        return $name;

//function
                    } elseif ((T_STRING === $token[$file_index][0]) && ('(' === $token[$file_index + 1][0])) {
                        $this->get_variable_property_name_lookup[$file_name][$file_index] = 'function';
                        return 'function';
//function
                    } elseif ((T_ECHO === $token[$file_index][0]) || (T_PRINT === $token[$file_index][0]) || (T_EXIT === $token[$file_index][0]) || (T_INT_CAST === $token[$file_index][0]) || (T_DOUBLE_CAST === $token[$file_index][0]) || (T_STRING_CAST === $token[$file_index][0]) || (T_ARRAY_CAST === $token[$file_index][0]) || (T_OBJECT_CAST === $token[$file_index][0]) || (T_BOOL_CAST === $token[$file_index][0]) || (T_UNSET_CAST === $token[$file_index][0])
                    ) {
                        $this->get_variable_property_name_lookup[$file_name][$file_index] = 'function';
                        return 'function';
                    } else {
                        $this->get_variable_property_name_lookup[$file_name][$file_index] = null;
                        return null;
                    }
                }
            } else {
                $this->get_variable_property_name_lookup[$file_name][$file_index] = null;
                return null;
            }
        } else {
            $this->get_variable_property_name_lookup[$file_name][$file_index] = null;
            return null;
        }
    }

    /**
     * get the name of the php variable or an object property by parsing the multi-dimensional associative array $files_tokens
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $file_index passed by reference with the index of the variable in the multi-dimensional array $files_tokens
     *
     * @return the name of the variable and in the $file_index parameter the last index of the variable in the multi-dimensional array $files_tokens
     */
    /* PN
   *
   * return array ($variable_name, $file_index)
   *
   *
   */
    function get_variable_property_complete_array_name($file_name, $file_index)
    {

// Change PN, update  $file_index
        if (isset($this->get_variable_property_complete_array_name_lookup[$file_name][$file_index])) {
//$this->count_find_match ++;
//$file_index = $this->get_variable_property_complete_array_name_lookup_file_index[$file_name][$file_index];
            return $this->get_variable_property_complete_array_name_lookup[$file_name][$file_index];
        }
// To.
// The value isn't tabled, evaluate it and add to the table
        $file_index_ant = $file_index;

//$this->count_execution++;
//  $t = microtime(true);
//get the variable name even if it is preceded by a '&'
        if ('&' === $this->files->files_tokens[$file_name][$file_index]) {
            $file_index++;
        }

        $variable_name = $this->get_variable_property_name($file_name, $file_index);

        $file_index = $this->get_variable_property_function_method_last_index($file_name, $file_index);

        if (($this->is_variable($file_name, $file_index)) || ($this->is_property($file_name, $file_index))) {

            if (((T_OBJECT_OPERATOR === $this->files->files_tokens[$file_name][$file_index + 1][0]) || (T_DOUBLE_COLON === $this->files->files_tokens[$file_name][$file_index + 1][0]))) {
                $file_index = $file_index + 1;
                while ((T_OBJECT_OPERATOR === $this->files->files_tokens[$file_name][$file_index][0]) || (T_DOUBLE_COLON === $this->files->files_tokens[$file_name][$file_index][0])) {
                    $file_index = $file_index + 2;
                }
            } else {
                $file_index++;
            }

            for ($i = $file_index, $count = count($this->files->files_tokens[$file_name]); $i < $count - 1; $i++) {
                $add_index = 0;
// test to see if it is an array variable
                if ('[' === $this->files->files_tokens[$file_name][$i]) {
                    $block_end_index = $this->find_match($file_name, $i, '[');
                    for ($j = $i; $j < $block_end_index; $j++) {
                        $add_index++;
                        if (is_array($this->files->files_tokens[$file_name][$j])) {
                            $variable_name = $variable_name . $this->files->files_tokens[$file_name][$j][1];
                        } else {
                            $variable_name = $variable_name . $this->files->files_tokens[$file_name][$j];
                        }
                    }
                    $variable_name = $variable_name . ']';
                } else {
                    break;
                }
                $i += $add_index;
            }
            $file_index = $i - 1;
//$this->time_execution_of += microtime(true) - $t;
            $this->get_variable_property_complete_array_name_lookup[$file_name][$file_index_ant] = array($variable_name, $file_index);
            return array($variable_name, $file_index);
        } else {
            $file_index = $file_index - 1;
//$this->time_execution_of += microtime(true) - $t;
            $this->get_variable_property_complete_array_name_lookup[$file_name][$file_index_ant] = array($variable_name, $file_index);
            return array($variable_name, $file_index);
        }
    }

    function get_object_name($name)
    {
        $prefix = explode('->', $name, 2);
        $object_name = $prefix[0];
        if ($object_name === $name) {
            $object_name = null;
        }

        return $object_name;
    }

    function get_object_property_index($file_name, $function_name, $property_name)
    {
        $prefix = explode('->', $property_name, 2);
        $object_property_index = $this->get_variable_index($file_name, $prefix[0], $function_name);
        return $object_property_index;
    }

    /**
     * Search for the most recent apearence of the variable in the multi-dimensional associative array $parser_variables.
     * This is done by searching backwards the the multi-dimensional associative array $parser_variables.
     *
     * @param string $variable_name with the name of the variable
     * @param string $function_name with the name of the function where the code is being executed.
     *
     * @return int with the index of the most recent apearence of the variable in the multi-dimensional associative array $parser_variables
     */
    function get_variable_index_o($file_name, $variable_name, $function_name)
    {
        $count = count($this->parser_variables);
        for ($i = $count - 1; $i >= 0; $i--) {

//note: PHP functions are not case sensitive
            if (($variable_name === $this->parser_variables[$i][_PHPI_NAME]) && (0 === strcasecmp($this->parser_variables[$i][_PHPI_FILE], $file_name)) && (0 === strcasecmp($this->parser_variables[$i][_PHPI_FUNCTION], $function_name))) {
                return $i;
            }
        }
        return null;
    }

    function get_variable_index($file_name, $variable_name, $function_name)
    {

//if (is_null($variable_name))
//$this->echo_h1('OOPxx' .' === ' . "get_variable_index($file_name, $variable_name, $function_name)", 'green');

        $function_name = strtoupper($function_name);
        $key = "$file_name#$variable_name#$function_name";
        if (isset($this->parser_variables_lookup["$key"])) {
            $c = count($this->parser_variables_lookup["$key"]);

//$xx = $this->parser_variables_lookup["$key"][$c - 1];
//if ('$language_na_message' === $variable_name)
//$this->echo_h1("$xx " . '$language_na_message' .' === ' . $variable_name, 'red');
// V1
// // More fast. But not yet all tested.
//$variable_index = $this->parser_variables_lookup["$key"][$c - 1];
//return $variable_index;
            return $this->parser_variables_lookup["$key"][$c - 1];

// V2
// search max index
//      $variable_index = -1;
//      for ($i = $c - 1; $i >= 0; $i--) {
//        if (isset($this->parser_variables_lookup["$key"][$i])) {
//          if ($variable_index < $this->parser_variables_lookup["$key"][$i]) {
//            $variable_index = $this->parser_variables_lookup["$key"][$i];
//          }
//        }
//      }
//
//      $_return = $this->parser_variables_lookup["$key"][$c - 1];
//
//      if ($_return != $variable_index)
//        $this->echo_h1("DIFF $_return != $variable_index", 'red');
//      if ($variable_index == -1)
//        return null;
//      else
//        return $variable_index;
//      // end V2
        } else {
//$variable_index = null;
            return null;
        }


//    $count = count($this->parser_variables);
//    for ($i = $count - 1; $i >= 0; $i--) {
//      //note: PHP functions are not case sensitive
//      if (( $variable_name === $this->parser_variables[$i][_PHPI_NAME] ) && (0 === strcasecmp($this->parser_variables[$i][_PHPI_FILE], $file_name)) && (0 === strcasecmp($this->parser_variables[$i][_PHPI_FUNCTION], $function_name) )) {
//        if ($i === 1190)
//          $this->echo_h1("$key - $i", 'red');
//        return $i;
//      }
//    }
//    // $this->echo_h1("null", 'red');
//    return null;
    }

    /**
     * get the multi-dimensional associative array with the PHP tokens
     *
     * @return the multi-dimensional associative array $files_tokens
     */
    function get_files_tokens()
    {
        return $this->files->files_tokens;
    }

    /**
     * get the multi-dimensional associative array with the user defined functions
     *
     * @return the multi-dimensional associative array $files_functions
     */
    function get_files_functions()
    {
        return $this->files_functions;
    }

    /**
     * get the multi-dimensional associative array with all the functions used in the code
     *
     * @return the multi-dimensional associative array $used_Functions
     */
    function get_used_functions()
    {
        return $this->used_functions;
    }

    /**
     * get the array with the parser debug messages
     *
     * @return the array with the parser debug messages $parserDebug
     */
    function get_parser_debug()
    {
        return $this->parser_debug;
    }

    /**
     * get the multi-dimensional associative array with the PHP variable attributes
     *
     * @return the multi-dimensional associative array $parser_variables
     */
    function get_parser_variables()
    {
        return $this->parser_variables;
    }

    /**
     * get the multi-dimensional associative array with the includes and requires
     *
     * @return the multi-dimensional associative array $filesIncludeRequire
     */
    function get_files_include_require()
    {
        return $this->files_include_require;
    }

    /**
     * Show debug information
     *
     * @param string $message with the debug message
     */
    function debug($message)
    {
        $this->parser_debug[] = $message;
    }

    /**
     * Show debug information html formated
     *
     * @param string $message with the debug message
     */
    function debug2($message, $parameters)
    {
// header
        $m2 = str_replace('(', "<td>(</td><td>", $parameters);
        $m2 = str_replace(",", "</td><td>", $m2);
        $m2 = str_replace(")", "</td><td>)", $m2);

        $m2 = str_replace("main_parser", "<span style='color:blue'><b>main_parser [$this->main_parser_level]</b></span>", $m2);
        $m2 = str_replace("parse_variable_property_vulnerability", "<span style='color:green'><b>parse_variable_property_vulnerability</b></span>", $m2);
        $m2 = str_replace("parse_variable_property", "<span style='color:maroon'><b>parse_variable_property</b></span>", $m2);
//$m2 = str_replace("", "<span style='color:maroon'><b></b></span>", $m2);
        $m2 = str_replace("_vulnerability", "<span style='color:red'><b>_vulnerability</b></span>", $m2);

// Data
//$m = str_replace('(', "<td>(</td><td>", $message);
        $m = ereg_replace('[-A-Za-z_ ]+\(', "<th></th><td>(</td><th>", $message);
        $m = str_replace(",", "</th><th>", $m);
        $m = str_replace(")", "</td><td>)", $m);
        $m = str_replace('C:\\Users\\pnunes\\Desktop\\Dropbox\\_PhD\\php_tests\\Core\phpsafe-oop_html\\test\\', " ", $m);

//$parser_variables_lookup = $this->show_parser_variables_lookup_2(null);
        $parser_variables_lookup = "";
        $this->parser_debug2_counter++;
        $mm = "<tr><td>$this->parser_debug2_counter</td><td>$m2</td></tr><tr><td>$m</td><td>$parser_variables_lookup</td></tr>";
        $this->parser_debug2_text .= $mm;

        if ($this->parser_debug2_flag) {
            if ($this->parser_debug2_flag_file) {
                fprintf($this->parser_debug2_file_stream, "%s", $mm);
                fflush($this->parser_debug2_file_stream);
            }
        }
    }

}

// The ending PHP tag is omitted. This is actually safer than including it.