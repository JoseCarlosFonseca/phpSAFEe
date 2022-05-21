<?php

/**
 *
 * phpSAFE - PHP Security Analysis For Everyone
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
 * 2014-10-31, trainted/vulnerability ...  NOK
 * 2014-11-01, trainted/vulnerability ...  NOK
 * 2014-11-03, trainted/vulnerability ...  NOK,
 *       add   in function parse_user_defined_function_method_vulnerability(), UPDATE location calling
 *             $this->parser_variables[$n][_PHPI_LINE] = $called_function_line;
 *             $this->parser_variables[$n][_PHPI_FUNCTION] = $called_function_name;
 *             $this->parser_variables[$n][_PHPI_FILE] = $called_function_file_name;
 * 2014-11-04,
 *       fix callings with less arguments than parameters ( if ($parameter_number === $max_parameter_number) { ... )
 *       fix trainted/vulnerability ...  OK in filtered functions (add if ($variable_filter != "") { ....)
 * 2014-11-05
 *       add  analyze function with optional parameters once. OK
 *
 * 2015-02-04- Change
 *  $this->parse_function_method($file_name, $function_name, $i);
 *    TO
 *  $this->parse_function_method($file_name, $class_name, $function_name, $i);
 *
 *  function parse_other_function_method_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $called_function_name) {
 *    TO
 * function parse_other_function_method_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $called_function_name) {
 *
 *
 * function parse_user_defined_function_method_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $called_function_name, $called_function_index) {
 * TO
 * function parse_user_defined_function_method_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $called_function_name, $called_function_index) {
 *
 *
 */
define('APP', 'phpSAFE - PHP Security Analysis For Everyone');

 if (isset($_SERVER['SERVER_PORT'])) {
	$port = $_SERVER['SERVER_PORT'];
	$base_url = "http://" . $_SERVER['SERVER_NAME'] . ":$port" . dirname($_SERVER["REQUEST_URI"]) . '/';
} else {
	$base_url ="";
}

if (!defined('BASE_URL')) {
    define('BASE_URL', $base_url);
}

require_once 'vulnerability_classification.php';
require_once 'class-vulnerable-input.php';
require_once 'class-vulnerable-output.php';
require_once 'class-vulnerable-filter.php';
require_once 'class-php-parser.php';

//TODO context checking
//(see http://wp.tutsplus.com/tutorials/creative-coding/data-sanitization-and-validation-with-wordpress/
//and http://codex.wordpress.org/Data_Validation
//and http://fieldguide.automattic.com/avoiding-xss/)
//
//TODO optimize variables by reducing the number of variables
//Use only input and output variables, and maybe variables that are filtered/unfiltered
//Do the vulnerability check on top of this
class PHP_SAFE extends PHP_Parser
{

    protected $_current_parsed_file;   // not in use

    /**
     * Multi-dimensional associative array with the PHP vulnerable variables attributes
     * @var array
     */
    protected $vulnerable_variables;

    /**
     * Multi-dimensional associative array with the PHP vulnerable variables attributes
     * @var array
     */
    protected $non_vulnerable_variables;


    /**
     * Multi-dimensional associative array with the PHP output variables attributes
     * @var array
     */
    protected $output_variables;
		
		
	 function  getFunctionVulnType($called_function_name) {
			$type = 'UNKNOWN';
        foreach (Vulnerable_Output2::$OUTPUT_FUNCTIONS as $key => $value) {
            foreach ($value as $output) {
                if (0 === strcasecmp($output, $called_function_name)) {
                    $type = $key;
                    break;
                }
            }
        }
		
		return $type;
	 }

		
		 function show_used_functions($parsed_file_ini, $output_dir)
    {
        $this->show_used_functions_SS($parsed_file_ini, $this->used_functions, 'Used Functions', $this->echo_used_functions, $output_dir .  "UsedFunctions.html", $this->file_write_used_functions);
    }
		
		function show_file_functions2($parsed_file_ini, $output_dir)
    {
		     // CSV
        $this->show_file_functions_SS($parsed_file_ini, $this->files_functions, 'File Functions', $this->echo_file_functions, $output_dir . "FileFunctions.csv", $this->file_write_file_functions);
    }
		
		function show_file_functions($parsed_file_ini, $output_dir)
    {
        $this->show_used_functions_SS($parsed_file_ini, $this->files_functions, 'File Functions', $this->echo_file_functions, $output_dir . "FileFunctions.html", $this->file_write_file_functions);
    }
		
		
    /**
     *
     */
    function show_vulnerable_variables($parsed_file_ini, $output_dir)
    {
        $this->echo_vulnerable_variables = false;
        return $this->show_variables($parsed_file_ini, $this->vulnerable_variables, 'Vulnerable Variables', $this->echo_vulnerable_variables, $output_dir . "Vuln.html", $this->file_write_vulnerable_variables);
    }


    function show_non_vulnerable_variables($parsed_file_ini, $output_dir)
    {
        // 2016-11-20
        $this->echo_non_vulnerable_variables = false;
        return $this->show_variables($parsed_file_ini, $this->non_vulnerable_variables, 'Non-vulnerable Variables', $this->echo_non_vulnerable_variables, $output_dir . "Non-vuln.html", $this->file_write_non_vulnerable_variables);
    }

    function show_vulnerable_variables_with_dependencies($parsed_file_ini, $output_dir)
    {
        $this->echo_vulnerable_variables_with_dependencies = false;
        $this->file_write_vulnerable_variables_with_dependencies = true;
        return $this->show_vulnerable_variables_with_dependencies_($parsed_file_ini, true, $this->parser_variables, 'Vulnerable Variables With Depencencies', $this->echo_vulnerable_variables_with_dependencies, $output_dir . "VulnDep.html", $this->file_write_vulnerable_variables_with_dependencies);
    }

    function show_parser_variables_with_dependencies()
    {
        $this->show_vulnerable_variables_with_dependencies_(false, $this->parser_variables, 'Parser Variables With Depencencies', $this->echo_parser_variables_with_dependencies, "ParserWithDependenciesVariables.html", $this->file_write_parser_variables_with_dependencies);
    }

    /**
     *
     */
    function show_output_variables($parsed_file_ini, $output_dir)
    {
        $this->echo_output_variables = false;
        //$this->file_write_output_variables = true;
        return $this->show_variables($parsed_file_ini, $this->output_variables, 'Output Variables', $this->echo_output_variables, $output_dir . "OutputVariables.html", $this->file_write_output_variables);
        //function show_variables($parsed_file_ini, $variables, $text, $echo_html, $html_file_name, $write_in_file) {
    }

    /**
     * It is a user defined function so it is parsed
     *
     * note: You define a function with parameters, you call a function with arguments.
     *
     * @param string $file_name with the PHP file name of the calling function
     * @param string $function_name with the name of the function where the code is being executed, the calling function.
     *
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     *
     * @param string $called_function_start_index with the start index of tokens of the multi-dimensional array $files_tokens of the calling function
     * @param string $called_function_end_index with the start index of tokens of the multi-dimensional array $files_tokens of the calling function
     * @param string $called_function_name with the name of the function, the called function
     * @param int $called_function_index with the index name of the function, the called function
     */

    /**
     *
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $block_end_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @return int
     */
    function parse_user_defined_function_method_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $called_function_name, $called_function_index)
    {
        //$this->debug( sprintf( "%s:%s:<b><span style='color:cadetblue;'>%s</span></b> :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );
        //$this->echo_h1($this->files->files_tokens[$file_name][$block_start_index][0], "magenta");

        if ($this->parser_debug2_flag) {
            $this->debug2("parse_user_defined_function_method_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $called_function_name, $called_function_index )", 'parse_user_defined_function_method_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $called_function_name, $called_function_index )');
        }

        //found the code of the PHP user defined function
        $called_function_file_name = $this->files_functions[$called_function_index][_PHPI_FILE];
        $called_function_start_index = $this->files_functions[$called_function_index][_PHPI_START_INDEX];
        $called_function_end_index = $this->files_functions[$called_function_index][_PHPI_END_INDEX];
        $called_class_name = $this->files_functions[$called_function_index][_PHPI_CLASS];

        // Change
        $parser_variables_count_before_add_arguments = count($this->parser_variables);
        //echo "<p>Block I</p>";
        // To.
        /*
         *  add local variables (from the parameters of the function) based on the variables of the arguments
         */
        $first_called_function_variable_index = count($this->parser_variables);
        $parameter_number = 0;
        $max_parameter_number = count($this->files_functions[$called_function_index][_PHPI_PARAMETERS]);
        for ($i = $block_start_index + 1; $i < $block_end_index; $i++) {
            //get the argument of the call of the function
            $next_argument_index = $this->find_token($file_name, $i, ',');
            if ($next_argument_index > $block_end_index) {
                $next_argument_index = $block_end_index;
            }
            //the argument may be an expression, instead of a single variable
            $expression = $this->parse_expression_vulnerability($file_name, $class_name, $function_name, $i, $next_argument_index, null, null);
            $called_function_parameter_name = $this->files_functions[$called_function_index][_PHPI_PARAMETERS][$parameter_number][_PHPI_PARAMETER_NAME];

            //If the variable is an object and it is tainted, then the contents of that variable are also tainted
            //so get the object part of the property
            $object_variable_name = $this->get_object_name($called_function_parameter_name);
						
																// 2016-11-27, SS
							$previous_containing_function = $this->find_previous_containing_function_from_index($file_name, $block_start_index);
							//echo $previous_containing_function;
							// 2016-11-27, SS

            //create a local variable of the called function with the name of the parameter and the contents of the argument
            $this->parser_variables[] = array(
                _PHPI_NAME => $called_function_parameter_name,
                _PHPI_OBJECT => $object_variable_name,
                _PHPI_CLASS => null,
                _PHPI_SCOPE => 'local',
                _PHPI_VARIABLE_FUNCTION => 'variable',
                _PHPI_EXIST_DESTROYED => EXIST,
                _PHPI_CODE_TYPE => PHP_CODE,
                _PHPI_INPUT => REGULAR_VARIABLE,
                _PHPI_OUTPUT => REGULAR_VARIABLE,
                _PHPI_FUNCTION => $called_function_name,
                _PHPI_FILE => $called_function_file_name,
                _PHPI_LINE => $this->files_functions[$called_function_index][_PHPI_PARAMETERS][$parameter_number][_PHPI_LINE],
                _PHPI_TAINTED => $expression[_PHPI_TAINTED],
                _PHPI_VULNERABILITY => $expression[_PHPI_VULNERABILITY],
                _PHPI_START_INDEX => $this->files_functions[$called_function_index][_PHPI_START_INDEX],
                _PHPI_END_INDEX => $this->files_functions[$called_function_index][_PHPI_START_INDEX],
                _PHPI_DEPENDENCIES_INDEX => $expression[_PHPI_DEPENDENCIES_INDEX],
                _PHPI_VARIABLE_FILTER => null,
                _PHPI_VARIABLE_REVERT_FILTER => null,
								_PHPI_SENSITIVE_SINK =>  $previous_containing_function,
								_PHPI_SENSITIVE_SINK_VULNERABILITY => $this->getFunctionVulnType($previous_containing_function)
            );

            // Change, add. Parallel array
            // if not exists, 4nd key '0' else n+1
            //array_key_exists
            $fln = $called_function_file_name;
            $vn = $called_function_parameter_name;
            $fn = $called_function_name;
            $this->add_parser_variables_lookup($fln, $vn, $fn, count($this->parser_variables) - 1);
            //To.

            $i = $next_argument_index;
            $parameter_number++;
            //if all the parameters have been parsed or
            //if the function definition has less parameters than there are arguments continue with the existing arguments
            if (($next_argument_index === $block_end_index) || ($parameter_number >= $max_parameter_number)) {
                break;
            }
        }
        // Change
        $parser_variables_count_after_add_arguments = count($this->parser_variables) - 1;
        // To.

        /*
         * the variables of the parameters of the called function are already created so
         * parse the contents of the called function
         * if the function returns a value, a variable for the return value is created with the name of the called function
         *
         */
        //skip the name of the called function
        $called_function_start_index = $this->find_match($called_function_file_name, $called_function_start_index, '(');

        // Change
        // parse the contents of the called function
        //$op = 1;
        if (true) {
            //if (($op == 1) && ( $parameter_number === $max_parameter_number)) {
            //if ($parameter_number === $max_parameter_number) {
            $called_function_name_upper = strtoupper($called_function_name);
            //$class_name= "";
            $key = "$called_function_file_name#$class_name#$called_function_name_upper#$called_function_start_index#$called_function_end_index";
            //echo "<p>KEY FUNTION $key</p>";
            if ((isset($this->parser_variables_user_functions_lookup["$key"]) &&
                ($this->parser_variables_user_functions_lookup["$key"]['parameter_number'] === $parameter_number))
            ) {
                // parameters list
                $parameters_count = count($this->files_functions[$called_function_index][_PHPI_PARAMETERS]);
                //echo " já $parameters_count/$parameter_number $called_function_name_upper<br>";
                //$parameters_count = $parameter_number; // equal or less

                $parameters_list = array();
                $first_parameters_occorrence = array();
                for ($j = 0; $j < $parameter_number; $j++) {
                    $pn = $this->files_functions[$called_function_index][_PHPI_PARAMETERS][$j][_PHPI_PARAMETER_NAME];
                    $parameters_list ["$pn"] = $pn;
                    $first_parameters_occorrence["$pn"] = 0;
//                $this->echo_h1(" Parameters $called_function_name_upper ($j - $pn)", 'red'); 
                }
                // adds two blocks os variables
                // 1- bind arguments (argumentes as dependencies previous call)
                // 2- stored variables (of the inside of the function)
                // retrieve parser variables RCV
                // bind argument variables with the first occurreny in RCV.
                //echo "Já";
                //$this->main_parser($called_function_file_name, $called_function_name, $called_function_start_index, $called_function_end_index);
                // 1- bind arguments
                // retrieve  variables, and add to the end of parser variables
                $n = count($this->parser_variables);
                $parser_variables_count_before = $n;

                for ($i = $this->parser_variables_user_functions_lookup["$key"]['vib']; $i <= $this->parser_variables_user_functions_lookup["$key"]['vie']; $i++) {
                    $this->parser_variables[$n] = $this->parser_variables[$i];     //$this->parser_variables_user_functions_lookup["$key"]['v'][$i];
                    $vn = $this->parser_variables[$n][_PHPI_NAME];
                    $line = $this->parser_variables[$n][_PHPI_LINE];

                    // update the calling location
                    if ($vn === $called_function_name) {
                        $called_function_line = $this->files->files_tokens[$file_name][$block_start_index - 1][2];
                        //$this->echo_h1 ("$file_name $function_name | $called_function_file_name $called_function_name | $vn $line $called_function_line", 'blue');
                        $this->parser_variables[$n][_PHPI_LINE] = $called_function_line;
                        // echo "fn (" . $this->parser_variables[$n][_PHPI_FUNCTION] . ") = cfn($called_function_name)  vn($vn)<br>";
                        $this->parser_variables[$n][_PHPI_FUNCTION] = $called_function_name;
                        $this->parser_variables[$n][_PHPI_FILE] = $called_function_file_name;
                    }
                    $this->add_parser_variables_lookup($called_function_file_name, $vn, $called_function_name, $n);

                    // remove dependencies os the first call
                    // $this->parser_variables[$n][_PHPI_DEPENDENCIES_INDEX] = null;
                    // update dependencies according with new positions (index dep - index)= shift
                    // $i - index
                    $nd = count($this->parser_variables[$i][_PHPI_DEPENDENCIES_INDEX]);
                    for ($j = 0; $j < $nd; $j++) {
                        $old_index = $this->parser_variables[$i][_PHPI_DEPENDENCIES_INDEX][$j];
                        if (is_numeric($old_index)) {
                            $shift = $old_index - $i;
                            $this->parser_variables[$n][_PHPI_DEPENDENCIES_INDEX][$j] = $n + $shift;
//                            if ($n === 1241) {
//                               //if ($n  === 1192) {
//                                  $new_index = $n + $shift;
//                                    $vi = $this->parser_variables[$i][_PHPI_NAME];
//                                    $vid = $this->parser_variables[$old_index][_PHPI_NAME];
//                                    $vn = $this->parser_variables[$n][_PHPI_NAME];
//                                    $vnd = $this->parser_variables[$new_index][_PHPI_NAME];
//                                    $vi_ = "$vi ($i) dep: $vid ($old_index)<br>";
//                                    $vn_ = "$vn ($n) dep: $vnd ($new_index)<br>";
//                                $this->echo_h1("$vi_ $vn_ shift($shift)", 'red');
//                            }
                            //if ($shift === 0)
                            // $this->echo_h1 ($key, 'red');
                            //$xx = $this->parser_variables[$n][_PHPI_DEPENDENCIES_INDEX][$j];
                            // $this->echo_h1 ("$this->parser_variables[$n][_PHPI_DEPENDENCIES_INDEX][$j] = $n + $shift ($xx)", 'green');
                        } //else {
                        //$f = $this->files->files_tokens_names[$file_name] . " [$file_name]" ;
                        //$this->echo_h1("ERROR NOT IS_NUMERIC num desps $nd ($f) $old_index = this->parser_variables[$i][_PHPI_DEPENDENCIES_INDEX][$j]", 'red');
                        //}
                        //if ($n===1220)
                        //echo "$shift     $i/" .($i + $shift) . "     $n/" . ($n + $shift) . "<br>";
                    }
                    $n++;
                }
                $parser_variables_count_after = count($this->parser_variables) - 1;

                // the parameters are connected, classify the parameters
                // classify 1st occurrence of the parameters in body, bind with the last occurrence in ...
                //$mark_first_bind = array();
                for ($j = 0; $j < $parameter_number; $j++) {
                    $pn = $this->files_functions[$called_function_index][_PHPI_PARAMETERS][$j][_PHPI_PARAMETER_NAME];
                    // searchs in parser variables of the inside function
                    for ($k = $parser_variables_count_before; $k <= $parser_variables_count_after; $k++) {
                        // is parameter?
                        //$this->echo_h1("$k", 'blue');
                        //$this->echo_h1 ("$k $vn", 'blue');
                        //if ('$language_na_message' === $pn)
                        if (0 === strcasecmp($this->parser_variables[$k][_PHPI_NAME], $pn)) {
                            // have zero or one depencence
                            if (is_array($this->parser_variables[$k][_PHPI_DEPENDENCIES_INDEX])) {
                                $dep_index = $this->parser_variables[$k][_PHPI_DEPENDENCIES_INDEX][0];
                                //$ccc = count($this->parser_variables[$k][_PHPI_DEPENDENCIES_INDEX]);
                                //$this->echo_h1("Count deps paratmeters:  $ccc ", 'green');
                                if (is_numeric($dep_index)) {
                                    //$vn = $this->parser_variables[$k][_PHPI_NAME];
                                    //$vn_dep = $this->parser_variables[$dep_index][_PHPI_NAME];

                                    $tainted = $this->parser_variables[$dep_index][_PHPI_TAINTED];
                                    if ($tainted === _PHPI_TAINTED) {
                                        $vul = $this->parser_variables[$dep_index][_PHPI_VULNERABILITY];
                                        //$this->echo_h1("PAR LIST $j ($pn) PAR $k ($vn) DEP PAR $dep_index ($vn_dep - $tainted)", 'blue');
                                        //if ('$language_na_message' === $pn)
                                        //  $this->echo_h1("$k ($pn) $dep_index ($pn) $tainted/$vul", 'magenta');

                                        $this->parser_variables[$k][_PHPI_TAINTED] = $tainted;
                                        $this->parser_variables[$k][_PHPI_VULNERABILITY] = $vul;   // filtered
                                    }
                                } //else {
                                //$f = $this->files->files_tokens_names[$file_name] . " [$file_name]" ;
                                //$this->echo_h1("ERROR NOT IS_NUMERIC ($f)  = this->parser_variables[$k][_PHPI_DEPENDENCIES_INDEX][0]", 'orange');
                                // }
                                //$this->echo_h1("$k ($pn) $dep_index ($pn)", 'magenta');
                            } else {
                                //$this->echo_h1("ERROR HAVE zero deps dep_index = $this->parser_variables[$k][_PHPI_DEPENDENCIES_INDEX][0]", 'orange');
                            }
                        }
                    }
                }

                // optional parameters do not have dependencies, force it
                //2014-11-05
                for ($j = $parameter_number; $j < $parameters_count; $j++) {
                    $pn = $this->files_functions[$called_function_index][_PHPI_PARAMETERS][$j][_PHPI_PARAMETER_NAME];
                    // searchs in parser variables of the inside function
                    for ($k = $parser_variables_count_before; $k <= $parser_variables_count_after; $k++) {
                        // is parameter?
                        //$this->echo_h1("$k", 'blue');
                        //$this->echo_h1 ("$k $vn", 'blue');
                        //if ('$language_na_message' === $pn)
                        if (0 === strcasecmp($this->parser_variables[$k][_PHPI_NAME], $pn)) {
                            $this->parser_variables[$k][_PHPI_DEPENDENCIES_INDEX] = null;
                            $this->parser_variables[$k][_PHPI_TAINTED] = 'untainted';
                            $this->parser_variables[$k][_PHPI_VULNERABILITY] = 'unknown';
                        }
                    }
                }

                // variable in the body, local parameters and others.
                //for ($k = $parser_variables_count_after; $k >= $parser_variables_count_before; $k--) {
                for ($k = $parser_variables_count_before; $k <= $parser_variables_count_after; $k++) {
                    $n = count($this->parser_variables[$k][_PHPI_DEPENDENCIES_INDEX]);
                    if ($n > 0) {
                        $vn = $this->parser_variables[$k][_PHPI_NAME];
                        //variable_filter	variable_revert_filter

                        $variable_filter = $this->parser_variables[$k][_PHPI_VARIABLE_FILTER];
                        if ($variable_filter != "") {
                            $tainted = $this->parser_variables[$k][_PHPI_TAINTED];
                            $variable_revert_filter = $this->parser_variables[$k][_PHPI_VARIABLE_REVERT_FILTER];
                            $vul = $this->parser_variables[$k][_PHPI_VULNERABILITY];
                            $this->parser_variables[$k][_PHPI_TAINTED] = 'untainted';
                            //$this->echo_h1("$k PAR $vn tainted($tainted) vulnerability($vul) variable_filter($variable_filter) variable_revert_filter($variable_revert_filter) ", 'magenta');
                        } else {
                            $c = 0;
                            for ($i = 0; $i < $n; $i++) {
                                // ver.
                                $dindex = $this->parser_variables[$k][_PHPI_DEPENDENCIES_INDEX][$i];
                                //$this->echo_h1("($k)-$i -$n ($dindex)", 'blue');
                                if (is_numeric($dindex)) {
                                    //$dvn = $this->parser_variables[$dindex][_PHPI_NAME];
                                    // $this->echo_h1($this->parser_variables[$dindex][_PHPI_TAINTED], 'black');
                                    if ($this->parser_variables[$dindex][_PHPI_TAINTED] === _PHPI_TAINTED) {
                                        $c++;
                                        // tainted
                                        $this->parser_variables[$k][_PHPI_TAINTED] = _PHPI_TAINTED;
                                        $this->parser_variables[$k][_PHPI_VULNERABILITY] = $this->parser_variables[$dindex][_PHPI_VULNERABILITY];
                                        // $this->echo_h1(" $k " . $this->parser_variables[$dindex][_PHPI_VULNERABILITY] . "<br>", 'red');
                                        break;
                                    }
                                }
                                //$this->echo_h1("($k)", 'red');
                                //$this->echo_h1("$k-$i-$n($c) $vn $dvn ($dindex)", 'maroon');
                            }
                        }
                    }
                }
            } else {
                //echo "1st";
                $parser_variables_count_before = count($this->parser_variables);
                // OOP_MP
                //$called_class_name = "";
                $this->main_parser($called_function_file_name, $called_class_name, $called_function_name, $called_function_start_index, $called_function_end_index);
                $parser_variables_count_after = count($this->parser_variables);
                //$this->echo_h1("count pv $parser_variables_count_before/$parser_variables_count_after", 'black');
                // stores separately parser variables for the current function
                //$this->parser_variables_user_functions[$i] = $this->parser_variables;
                // key
                // variable index begin and end
                $this->parser_variables_user_functions_lookup["$key"]['vib'] = $parser_variables_count_before;
                $this->parser_variables_user_functions_lookup["$key"]['vie'] = $parser_variables_count_after - 1;
                $this->parser_variables_user_functions_lookup["$key"]['parameter_number'] = $parameter_number;
                //echo "OLD $parameter_number <br>";
                // store variables, nor necessary !
                //for ($i=$this->parser_variables_user_functions_lookup["$key"]['vib']; $i<= $this->parser_variables_user_functions_lookup["$key"]['vie'] ; $i++){
                //    $this->parser_variables_user_functions_lookup["$key"]['v'][] = $this->parser_variables[$i];
                //}
                //$c = count($this->parser_variables_user_functions_lookup);
                // $c .= "this->main_parser($called_function_file_name, $called_function_name, $called_function_start_index, $called_function_end_index)";
                //$this->echo_h1($c, 'black');
            }
            // To.
            // old
        } else {
            //echo "old";
            // bind parameters to inside function variables
            // OOP_MP
            //$called_class_name = "";
            $this->main_parser($called_function_file_name, $called_class_name, $called_function_name, $called_function_start_index, $called_function_end_index);
        }
        /*
         * destroy the local variables
         *
         */
        //find the file line number of the function call
        $calling_function_file_line_number = $this->files->files_tokens[$file_name][$block_start_index - 1][2];

        //find the last file line number of the called function
        $called_function_file_line_number = $this->files_functions[$called_function_index][_PHPI_END_LINE];

        //create a calling function variable from the variable of the return of the called function
        //create calling function variables from the global variables used in the called function
        //destroy all the variables used within the function
        //search for the variables used in the called function
        $count = count($this->parser_variables);
        //echo "<p>Count BEFORE UPDATE $count</p>";
        for ($i = $count - 1; $i >= $first_called_function_variable_index; $i--) {

            //note: PHP functions are not case sensitive
            if ((0 === strcasecmp($this->parser_variables[$i][_PHPI_FUNCTION], $called_function_name)) && ($called_function_file_name === $this->parser_variables[$i][_PHPI_FILE]) && (EXIST === $this->parser_variables[$i][_PHPI_EXIST_DESTROYED])) {

                //a variable used in the called function was found
                //search if a variable of the called function with the same name was already destroyed
                $variable_index = $this->get_variable_index($called_function_file_name, $this->parser_variables[$i][_PHPI_NAME], $called_function_name);

                //it the variable was not yet destroyed, then destroy it by creating a new variable destroyed
                if (EXIST === $this->parser_variables[$variable_index][_PHPI_EXIST_DESTROYED]) {
                    //test if the variable is the return of the called function
                    if ($called_function_name === $this->parser_variables[$i][_PHPI_NAME]) {
                        // Change, previous value
                        $fln_previous = $this->parser_variables[$i][_PHPI_FILE];
                        $fn_previous = $this->parser_variables[$i][_PHPI_FUNCTION];
                        $vn_previous = $this->parser_variables[$i][_PHPI_NAME];
                        // To.
                        //if the variable is the return of the function, then it is updated
                        $this->parser_variables[$i][_PHPI_FUNCTION] = $function_name;
                        $this->parser_variables[$i][_PHPI_FILE] = $file_name;
                        $this->parser_variables[$i][_PHPI_LINE] = $calling_function_file_line_number;
                        $this->parser_variables[$i][_PHPI_START_INDEX] = $block_start_index;
                        $this->parser_variables[$i][_PHPI_END_INDEX] = $block_end_index;

                        // Change
                        $fln = $file_name;
                        // delete old item
                        $this->delete_variable_index_with_lookup($fln_previous, $vn_previous, $fn_previous, $i);
                        // add new
                        $this->add_parser_variables_lookup($file_name, $vn_previous, $function_name, $i);

//                        $ccc = count($this->parser_variables_lookup["$key"]);
//                        $this->echo_h1("C($ccc)ADD: add_parser_variables_lookup($file_name, $vn_previous, $function_name, $i)<br> ", "orange");
                        //To.
                        continue;
                    } elseif ('global' === $this->parser_variables[$i][_PHPI_SCOPE]) {
                        //if it is a global variable then create a new variable in the calling function scope

                        $global_variable_index = $this->get_variable_index($file_name, $this->parser_variables[$i][_PHPI_NAME], $function_name);
                        if ($global_variable_index) {
                            $scope = $this->parser_variables[$global_variable_index][_PHPI_SCOPE];
                        } else {
                            $scope = 'local';
                        }
												
																		// 2016-11-27, SS
											$previous_containing_function = $this->find_previous_containing_function_from_index($file_name, $block_start_index);
											//echo $previous_containing_function;
											// 2016-11-27, SS

                        $this->parser_variables[] = array(
                            _PHPI_NAME => $this->parser_variables[$i][_PHPI_NAME],
                            _PHPI_OBJECT => $this->parser_variables[$i][_PHPI_OBJECT],
                            _PHPI_CLASS => null,
                            _PHPI_SCOPE => $scope,
                            _PHPI_VARIABLE_FUNCTION => $this->parser_variables[$i][_PHPI_VARIABLE_FUNCTION],
                            _PHPI_EXIST_DESTROYED => EXIST,
                            _PHPI_CODE_TYPE => $this->parser_variables[$i][_PHPI_CODE_TYPE],
                            _PHPI_INPUT => $this->parser_variables[$i][_PHPI_INPUT],
                            _PHPI_OUTPUT => $this->parser_variables[$i][_PHPI_OUTPUT],
                            _PHPI_FUNCTION => $function_name,
                            _PHPI_FILE => $file_name,
                            _PHPI_LINE => $calling_function_file_line_number,
                            _PHPI_TAINTED => $this->parser_variables[$i][_PHPI_TAINTED],
                            _PHPI_VULNERABILITY => $this->parser_variables[$i][_PHPI_VULNERABILITY],
                            _PHPI_START_INDEX => $block_start_index,
                            _PHPI_END_INDEX => $block_end_index,
                            _PHPI_DEPENDENCIES_INDEX => null, // array($i),  // 2015-01-22
                            _PHPI_VARIABLE_FILTER => null,
                            _PHPI_VARIABLE_REVERT_FILTER => null,
														_PHPI_SENSITIVE_SINK => $previous_containing_function,
														_PHPI_SENSITIVE_SINK_VULNERABILITY => $this->getFunctionVulnType($previous_containing_function)
                        );

                        // Change, add. Parallel array
                        // if not exists, 4nd key '0' else n+1
                        $fln = $file_name;
                        $vn = $this->parser_variables[$i][_PHPI_NAME];
                        $fn = $function_name;
                        $this->add_parser_variables_lookup($fln, $vn, $fn, count($this->parser_variables) - 1);
                        //To.
                    }

                    //destroy the variable of the called function
                    $this->parser_variables[] = array(
                        _PHPI_NAME => $this->parser_variables[$i][_PHPI_NAME],
                        _PHPI_OBJECT => $this->parser_variables[$i][_PHPI_OBJECT],
                        _PHPI_CLASS => null,
                        _PHPI_SCOPE => $this->parser_variables[$i][_PHPI_SCOPE],
                        //'variable_function' => $this->parser_variables[$i]['variable_function'],
                        _PHPI_VARIABLE_FUNCTION => $this->parser_variables[$i][_PHPI_VARIABLE_FUNCTION],
                        _PHPI_EXIST_DESTROYED => DESTROYED,
                        _PHPI_CODE_TYPE => $this->parser_variables[$i][_PHPI_CODE_TYPE],
                        _PHPI_INPUT => $this->parser_variables[$i][_PHPI_INPUT],
                        _PHPI_OUTPUT => $this->parser_variables[$i][_PHPI_OUTPUT],
                        _PHPI_FUNCTION => $called_function_name,
                        _PHPI_FILE => $this->parser_variables[$i][_PHPI_FILE],
                        _PHPI_LINE => $called_function_file_line_number,
                        _PHPI_TAINTED => UNTAINTED,
                        _PHPI_VULNERABILITY => UNKNOWN,
                        _PHPI_START_INDEX => $called_function_end_index,
                        _PHPI_END_INDEX => $called_function_end_index,
                        _PHPI_DEPENDENCIES_INDEX => array($i),
                        _PHPI_VARIABLE_FILTER => null,
                        _PHPI_VARIABLE_REVERT_FILTER => null,
												_PHPI_SENSITIVE_SINK => $this->parser_variables[$i][_PHPI_SENSITIVE_SINK],
												_PHPI_SENSITIVE_SINK_VULNERABILITY => $this->getFunctionVulnType($this->parser_variables[$i][_PHPI_SENSITIVE_SINK])
                    );
                    // Change, add. Parallel array
                    // if not exists, 4nd key '0' else n+1
                    $fln = $this->parser_variables[$i][_PHPI_FILE];
                    $vn = $this->parser_variables[$i][_PHPI_NAME];
                    $fn = $called_function_name;
                    $this->add_parser_variables_lookup($fln, $vn, $fn, count($this->parser_variables) - 1);
                    //To.
                }
            }
        }

        // old
//        for ($used_functions_index = 0, $count = count($this->used_functions); $used_functions_index < $count; $used_functions_index++) {
//            if (0 === strcasecmp($this->used_functions[$used_functions_index][_PHPI_NAME], $called_function_name)) {
//                break;
//            }
//        }
        //old
        // Change
        $key = strtoupper($called_function_name);
        if (isset($this->used_functions_lookup["$key"]))
            $used_functions_index = $this->used_functions_lookup["$key"];
        else
            $used_functions_index = null;
        // To.

        return $used_functions_index;
    }

    /**
     * If the called function is one of the output functions it is checked for tainted variables that could cause a vulnerability
     * If the caled function is not one of the output functions nothing is done
     * The called function is not really parsed because there is no source code
     *
     * TODO functions that have arguments that are not variables, like functions or expressions
     *
     * note: You define a function with parameters, you call a function with arguments.
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed, the calling function.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $block_end_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $called_function_name with the name of the function, the called function
     */
    function parse_other_function_method_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $called_function_name)
    {
        //  $class_name, new in 2015-02-04
        //$this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

        if ($this->parser_debug2_flag)
            $this->debug2("parse_other_function_method_vulnerability( $file_name, $class_name, $function_name, $block_start_index, $block_end_index, $called_function_name )", 'parse_other_function_method_vulnerability( $file_name, $class_name, $function_name, $block_start_index, $block_end_index, $called_function_name )');

        $called_function_name_b = "$file_name#$class_name#$called_function_name";
        $called_function_name_b = "$called_function_name";

        //secho "<p style='color:red'>OOP_z" . $called_function_name_b . "</p>";


        for ($used_functions_index = 0, $count = count($this->used_functions); $used_functions_index < $count; $used_functions_index++) {
            $called_function_name_a = $this->used_functions[$used_functions_index][_PHPI_FILE] . '#' . $this->used_functions[$used_functions_index][_PHPI_CLASS] . '#' . $this->used_functions[$used_functions_index][_PHPI_NAME];
            //echo "<p style='color:blue'>$used_functions_index " .  $called_function_name_a . " - $called_function_name_b </p>";
            $called_function_name_a = $this->used_functions[$used_functions_index][_PHPI_NAME];
            if (0 === strcasecmp($called_function_name_a, $called_function_name_b)) {
                ('none' === $this->used_functions[$used_functions_index][_PHPI_VULNERABILITY] ? $vulnerability_classification = null : $vulnerability_classification = $this->used_functions[$used_functions_index][_PHPI_VULNERABILITY]);
                ('not output' === $this->used_functions[$used_functions_index][_PHPI_OUTPUT] ? $output_variable_attribute = REGULAR_VARIABLE : $output_variable_attribute = OUTPUT_VARIABLE);
                ('not filter' === $this->used_functions[$used_functions_index][_PHPI_FILTER] ? $is_filtering_function = false : $is_filtering_function = true);
                ('not revert filter' === $this->used_functions[$used_functions_index][_PHPI_REVERT_FILTER] ? $is_revert_filtering_function = false : $is_revert_filtering_function = true);
                ('not input' === $this->used_functions[$used_functions_index][_PHPI_INPUT] ? $input_function_variable = REGULAR_VARIABLE : $input_function_variable = INPUT_VARIABLE);
                ('not other' === $this->used_functions[$used_functions_index][_PHPI_OTHER] ? $is_other_function = false : $is_other_function = true);
                break;
            }
        }
        //if (is_null($vulnerability_classification))
        //  die("..$called_function_name.....");

//$this->echo_h1("parse_other_function_method_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $called_function_name)", "maroon");  
        $expression = $this->parse_expression_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $output_variable_attribute, $vulnerability_classification);
        $object_variable_name = $this->get_object_name($called_function_name);
				
										
																// 2016-11-27, SS
							$previous_containing_function = $this->find_previous_containing_function_from_index($file_name, $block_start_index);
							//echo $previous_containing_function;
							// 2016-11-27, SS
 
 
        $variable_name = null; 
		$iFix = is_array($expression[_PHPI_DEPENDENCIES_INDEX])? count($expression[_PHPI_DEPENDENCIES_INDEX]):0;
        for ($i = 0, $count = $iFix; $i < $count; $i++) {
            $variable_index = $expression[_PHPI_DEPENDENCIES_INDEX] [$i];
            if ($i < $count - 1) {
                $variable_name = $variable_name . $this->parser_variables[$variable_index][_PHPI_NAME] . ', ';
            } else {
                //the space at the end allows not mistake this variable with the original variable in following variable dependencies
                $variable_name = $variable_name . $this->parser_variables[$variable_index][_PHPI_NAME] . ' ';
            }
//        echo ' $called_function_name '.$called_function_name.' $variable_name '.$variable_name.' $variable_index '.$variable_index."AQUI<br />";
        }
        if (is_null($variable_name)) {
            $variable_name = $called_function_name;
        }
//        $variable_name = $called_function_name;
        // it is a user defined function which there is no source code
        // or a PHP function that is not an input, nor a filtering, nor a revert filtering
        if ($is_other_function) {
            $tainted = $expression[_PHPI_TAINTED];
            $vulnerability_classification = $expression[_PHPI_VULNERABILITY];

            //add a new variable, which is the return value of the input function
            //If the variable is an object and it is tainted, then the contents of that variable are also tainted
            //so get the object part of the property
            $this->parser_variables[] = array(
//          _PHPI_NAME => $called_function_name,
                _PHPI_NAME => $variable_name,
                _PHPI_OBJECT => $object_variable_name,
                _PHPI_CLASS => $class_name,
                _PHPI_SCOPE => 'local',
                _PHPI_VARIABLE_FUNCTION => 'function',
                _PHPI_EXIST_DESTROYED => EXIST,
                _PHPI_CODE_TYPE => PHP_CODE,
                _PHPI_INPUT => REGULAR_VARIABLE,
                _PHPI_OUTPUT => REGULAR_VARIABLE,
                _PHPI_FUNCTION => $function_name,
                _PHPI_FILE => $file_name,
                _PHPI_LINE => $this->files->files_tokens[$file_name][$block_start_index - 1][2],
                _PHPI_TAINTED => $tainted,
                _PHPI_VULNERABILITY => $vulnerability_classification,
                _PHPI_START_INDEX => $block_start_index,
                _PHPI_END_INDEX => $block_end_index,
                _PHPI_DEPENDENCIES_INDEX => $expression[_PHPI_DEPENDENCIES_INDEX],
                _PHPI_VARIABLE_FILTER => null,
                _PHPI_VARIABLE_REVERT_FILTER => null,
								_PHPI_SENSITIVE_SINK => $called_function_name,
								_PHPI_SENSITIVE_SINK_VULNERABILITY => $this->getFunctionVulnType($called_function_name)
            );
            // Change, add. Parallel array
            // if not exists, 4nd key '0' else n+1
            $fln = $file_name;
            $vn = $variable_name;
            $fn = $function_name;
            $this->add_parser_variables_lookup($fln, $vn, $fn, count($this->parser_variables) - 1);
            //To.
        } else {
            //it is an input function
            if (INPUT_VARIABLE === $input_function_variable) {
                //add a new variable, which is the return value of the input function
                //If the variable is an object and it is tainted, then the contents of that variable are also tainted
                //so get the object part of the property

                $this->parser_variables[] = array(
                    _PHPI_NAME => $called_function_name,
                    _PHPI_OBJECT => $object_variable_name,
                    _PHPI_CLASS => $class_name,
                    _PHPI_SCOPE => 'local',
                    //'variable_function' => 'function', //in fact, this is not a variable. It is the return value of a function (an input function)
                    _PHPI_VARIABLE_FUNCTION => 'function',
                    _PHPI_EXIST_DESTROYED => EXIST,
                    _PHPI_CODE_TYPE => PHP_CODE,
                    _PHPI_INPUT => $input_function_variable,
                    _PHPI_OUTPUT => REGULAR_VARIABLE,
                    _PHPI_FUNCTION => $function_name,
                    _PHPI_FILE => $file_name,
                    _PHPI_LINE => $this->files->files_tokens[$file_name][$block_start_index - 1][2],
                    _PHPI_TAINTED => TAINTED,
                    _PHPI_VULNERABILITY => UNKNOWN,
                    _PHPI_START_INDEX => $block_start_index,
                    _PHPI_END_INDEX => $block_start_index,
                    _PHPI_DEPENDENCIES_INDEX => null,
                    _PHPI_VARIABLE_FILTER => null,
                    _PHPI_VARIABLE_REVERT_FILTER => null,
										_PHPI_SENSITIVE_SINK => $called_function_name,
										_PHPI_SENSITIVE_SINK_VULNERABILITY => $this->getFunctionVulnType($called_function_name)
                );
                // Change, add. Parallel array
                // if not exists, 4nd key '0' else n+1
                $fln = $file_name;
                $vn = $called_function_name;
                $fn = $function_name;
                $this->add_parser_variables_lookup($fln, $vn, $fn, count($this->parser_variables) - 1);
                //To.
            }

            //it is a filtering function
            if ($is_filtering_function) {
                $tainted = $expression[_PHPI_TAINTED];
                $vulnerability_classification = $expression[_PHPI_VULNERABILITY];
                if (TAINTED === $tainted) {
                    //untaint the original variable, because it is filtered
                    $tainted = UNTAINTED;
                    $vulnerability_classification = FILTERED;
                }
                $variable_filter = $called_function_name;

                //add a new variable, which is the return value of the input function
                //If the variable is an object and it is tainted, then the contents of that variable are also tainted
                //so get the object part of the property
                $this->parser_variables[] = array(
//          _PHPI_NAME => $called_function_name,
                    _PHPI_NAME => $variable_name,
                    _PHPI_OBJECT => $object_variable_name,
                    _PHPI_CLASS => $class_name,
                    _PHPI_SCOPE => 'local',
                    _PHPI_VARIABLE_FUNCTION => 'function',
                    _PHPI_EXIST_DESTROYED => EXIST,
                    _PHPI_CODE_TYPE => PHP_CODE,
                    _PHPI_INPUT => REGULAR_VARIABLE,
                    _PHPI_OUTPUT => REGULAR_VARIABLE,
                    _PHPI_FUNCTION => $function_name,
                    _PHPI_FILE => $file_name,
                    _PHPI_LINE => $this->files->files_tokens[$file_name][$block_start_index - 1][2],
                    _PHPI_TAINTED => $tainted,
                    _PHPI_VULNERABILITY => $vulnerability_classification,
                    _PHPI_START_INDEX => $block_start_index,
                    _PHPI_END_INDEX => $block_end_index,
                    _PHPI_DEPENDENCIES_INDEX => $expression[_PHPI_DEPENDENCIES_INDEX],
                    _PHPI_VARIABLE_FILTER => $variable_filter,
                    _PHPI_VARIABLE_REVERT_FILTER => null,
										_PHPI_SENSITIVE_SINK => $previous_containing_function,
										_PHPI_SENSITIVE_SINK_VULNERABILITY => $this->getFunctionVulnType($previous_containing_function)
                );
                // Change, add. Parallel array
                // if not exists, 4nd key '0' else n+1
                $fln = $file_name;
                $vn = $variable_name;
                $fn = $function_name;
                $this->add_parser_variables_lookup($fln, $vn, $fn, count($this->parser_variables) - 1);

                //To.
            }

            //it is a revert filtering function
            if ($is_revert_filtering_function) {
                //TODO revert filter actions

                $tainted = $expression[_PHPI_TAINTED];
                $vulnerability_classification = $expression[_PHPI_VULNERABILITY];
                $variable_revert_filter = $called_function_name;

                //add a new variable, which is the return value of the input function
                //If the variable is an object and it is tainted, then the contents of that variable are also tainted
                //so get the object part of the property
                $this->parser_variables[] = array(
//          _PHPI_NAME => $called_function_name,
                    _PHPI_NAME => $variable_name,
                    _PHPI_OBJECT => $object_variable_name,
                    _PHPI_CLASS => $class_name,
                    _PHPI_SCOPE => 'local',
                    _PHPI_VARIABLE_FUNCTION => 'function',
                    _PHPI_EXIST_DESTROYED => EXIST,
                    _PHPI_CODE_TYPE => PHP_CODE,
                    _PHPI_INPUT => REGULAR_VARIABLE,
                    _PHPI_OUTPUT => REGULAR_VARIABLE,
                    _PHPI_FUNCTION => $function_name,
                    _PHPI_FILE => $file_name,
                    _PHPI_LINE => $this->files->files_tokens[$file_name][$block_start_index - 1][2],
                    _PHPI_TAINTED => $tainted,
                    _PHPI_VULNERABILITY => $vulnerability_classification,
                    _PHPI_START_INDEX => $block_start_index,
                    _PHPI_END_INDEX => $block_end_index,
                    _PHPI_DEPENDENCIES_INDEX => $expression[_PHPI_DEPENDENCIES_INDEX],
                    _PHPI_VARIABLE_FILTER => null,
                    _PHPI_VARIABLE_REVERT_FILTER => $variable_revert_filter,
										_PHPI_SENSITIVE_SINK => $previous_containing_function,
										_PHPI_SENSITIVE_SINK_VULNERABILITY => $this->getFunctionVulnType($previous_containing_function)
                );
                // Change, add. Parallel array
                // if not exists, 4nd key '0' else n+1
                $fln = $file_name;
                $vn = $variable_name;
                $fn = $function_name;
                $this->add_parser_variables_lookup($fln, $vn, $fn, count($this->parser_variables) - 1);
                //To.
            }
        }
        return $used_functions_index;
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
        //$this->debug( sprintf( "%s:%s:<b><span style='color:azure;'>%s</span></b>  :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

        if ($this->parser_debug2_flag)
            $this->debug2("parse_return_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index )", 'parse_return_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index )');

        $start_index = $block_start_index;
        if ('(' === $this->files->files_tokens[$file_name][$block_start_index]) {
            $start_index = $block_start_index + 1;
        }
        $expression = $this->parse_expression_vulnerability($file_name, $class_name, $function_name, $start_index, $block_end_index, null, null);

        // returns null if there is no variable resulting from the return of this function
        $variable_index = $this->get_variable_index($file_name, $function_name, $function_name);
				
				
																			// 2016-11-27, SS
							$previous_containing_function = $this->find_previous_containing_function_from_index($file_name, $block_start_index);
							//echo $previous_containing_function;
							// 2016-11-27, SS
 
				
        if (!is_null($variable_index)) {
            //if there is already a return value variable we just update it if the new variable is tainted
            //if the variable is tainted, then we have a vulnerability
            if ($expression[_PHPI_TAINTED] === TAINTED) {
                $this->parser_variables[$variable_index][_PHPI_TAINTED] = TAINTED;
                $this->parser_variables[$variable_index][_PHPI_VULNERABILITY] = $expression[_PHPI_VULNERABILITY];
                $this->parser_variables[$variable_index][_PHPI_DEPENDENCIES_INDEX] = $expression[_PHPI_DEPENDENCIES_INDEX];
            }//else do nothing
        } else {
            //add a new variable, which is the return value of the input function
            //If the variable is an object and it is tainted, then the contents of that variable are also tainted
            //so get the object part of the property
            $object_variable_name = $this->get_object_name($function_name);
            $this->parser_variables[] = array(
                _PHPI_NAME => $function_name,
                _PHPI_OBJECT => $object_variable_name,
                _PHPI_CLASS => null,
                _PHPI_SCOPE => 'local',
                _PHPI_VARIABLE_FUNCTION => 'function',
                _PHPI_EXIST_DESTROYED => EXIST,
                _PHPI_CODE_TYPE => PHP_CODE,
                _PHPI_INPUT => REGULAR_VARIABLE,
                _PHPI_OUTPUT => REGULAR_VARIABLE,
                _PHPI_FUNCTION => $function_name,
                _PHPI_FILE => $file_name,
                _PHPI_LINE => $this->files->files_tokens[$file_name][$block_start_index - 1][2],
                _PHPI_TAINTED => $expression[_PHPI_TAINTED],
                _PHPI_VULNERABILITY => $expression[_PHPI_VULNERABILITY],
                _PHPI_START_INDEX => $block_start_index,
                _PHPI_END_INDEX => $block_end_index,
                _PHPI_DEPENDENCIES_INDEX => $expression[_PHPI_DEPENDENCIES_INDEX],
                _PHPI_VARIABLE_FILTER => null,
                _PHPI_VARIABLE_REVERT_FILTER => null,
								_PHPI_SENSITIVE_SINK => $previous_containing_function,
								_PHPI_SENSITIVE_SINK_VULNERABILITY => $this->getFunctionVulnType($previous_containing_function)
            );
            // Change, add. Parallel array
            // if not exists, 4nd key '0' else n+1
            $fln = $file_name;
            $vn = $function_name;
            $fn = $function_name;
            $this->add_parser_variables_lookup($fln, $vn, $fn, count($this->parser_variables) - 1);
            //To.
        }
    }

    /**
     * Parse an expression containing variables and functions, recursively.
     * Determines the attributes tainted, vulnerability_classification, variable_dependencies_index that will be returned
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $output_variable_attribute with the attribute OUTPUT_VARIABLE or null, if the expression belongs to an output function or not
     * @param string $vulnerability_classification with the vulnerability classification attribute or null, if the expression belongs to an output function or not
     *
     * @return multi-dimensional associative array with the attributes tainted, vulnerability_classification, variable_dependencies_index
     */
    function parse_expression_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $output_variable_attribute, $vulnerability_classification)
    {
        // $this->debug( sprintf( "%s:%s:<b><span style='color:coral;'>%s</span></b> :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

        if ($this->parser_debug2_flag)
            $this->debug2("parse_expression_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $output_variable_attribute, $vulnerability_classification )", 'parse_expression_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $output_variable_attribute, $vulnerability_classification )');

        //$current_variable_index = count($this->parser_variables);
        $tainted = UNTAINTED;
        $variable_dependencies_index = null;


        // echo '<p>OOOP_1 '. $this->generate_code_from_tokens($this->files->files_tokens[$file_name], $block_start_index, $block_end_index+2) . '</p>';

        // EXISTING_ERROR_FIX_BY_PN
        for ($i = $block_start_index; $i <= $block_end_index; $i++) {
            $variable_index = null;
            /* OOP
             * If it is a class name replace it with de constructor.
             *
             */
            $token = $this->files->files_tokens[$file_name];
            $object_creation = false;
            $class_name = null;
            if (is_array($token[$i]) && ($token[$i][0] === T_NEW)) {
                $object_creation = true;
                $class_name = $token[$i + 1][1]; // Name of the class
                //    die('OOOP');

                // echo '<p>OOOP_2 '. $this->generate_code_from_tokens($this->files->files_tokens[$file_name], $i, $i+2) . '</p>';

            }

            // die('OOOP');

            $object_creation = false;
            // End: OOP
            /*
             * it is a variable or a property
             * add the variable and propagate the taint and vulnerability classification, if it is the case
             *
             */
            if (($this->is_variable($file_name, $i)) || ($this->is_property($file_name, $i))) {

                // add the variable to the multi-dimensional associative array $parser_variables
                $index = $this->parse_variable_property($file_name, $class_name, $function_name, $i);
                $variable_index = count($this->parser_variables) - 1;
                $i = $index;

                /*
                 * it is a function or a method
                 *
                 */
                //} elseif (($this->is_function($file_name, $i)) || ($this->is_method($file_name, $i))) { // original
            } elseif (($object_creation) || ($this->is_function($file_name, $i)) || ($this->is_method($file_name, $i))) {
                // parse the function, which will add the existing variables to the multi-dimensional associative array $parser_variables
                //echo "<p>this->parse_function_method($file_name, $function_name, $i)</p>";
                // OOP
                // echo '<p>OOOP_3 '. $this->generate_code_from_tokens($this->files->files_tokens[$file_name], $i, $i+2) . '</p>';

                if ($object_creation) {
                    //_PHPI_CLASS] = $this->files->files_tokens[$file_name][$block_start_index + 1][1];
                    echo "<p style='color:red;'>Object creation in ($function_name), class: $class - ";

                    echo '<p>OOOP_4 ' . $this->generate_code_from_tokens($this->files->files_tokens[$file_name], $i - 1, $i + 2) . '</p>';
                    // Find the construct of the class: $class
                    $save_i = $i + 1;
                    $save = $this->files->files_tokens[$file_name][$save_i];
                    $this->files->files_tokens[$file_name][$save_i] = "__construct";    // force

                    $function_method = $this->parse_function_method($file_name, $class_name, $function_name, $i + 1);
                    $i = $function_method[0];
                    $target_function_name = $function_method[1];
                    $used_function_index = $function_method[2];

                    $this->files->files_tokens[$file_name][$save_i] = $save;
                } else { // OOP PEV

                    //echo "<p style='color:blue;'>function or method ($target_function_name) - ";
                    //echo $this->generate_code_from_tokens($this->files->files_tokens[$file_name], $i, $i) . '</p>';

                    $function_method = $this->parse_function_method($file_name, $class_name, $function_name, $i);
                    $i = $function_method[0];
                    $target_function_name = $function_method[1];
                    $used_function_index = $function_method[2];

                    // echo "<p style='color:blue;'>function or method ($target_function_name) - [$used_function_index] -  ";
                    // echo $this->generate_code_from_tokens($this->files->files_tokens[$file_name], $i, $i) . '</p>';
                    //var_dump($function_method);

//          echo count($this->used_functions) . 'TFN: ' . $target_function_name .  ' - Index:' . $used_function_index . ' - FN:' . $function_name .  '<br>';
//          //var_dump($this->used_functions[$used_function_index]);
//          foreach ($this->used_functions[$used_function_index] as $key => $value) {
//             echo "$key $value<br>";
//          }
//          var_dump($this->files_functions_lookup);

                }

                /*
                 * update variable attributes
                 *
                 */
                //  $used_function_index is null if the function is already being executed
                //  NOTE: we prevent the recursive execution of functions
                if (is_null($used_function_index)) {
                    continue;
                    //it is a user defined PHP function from which we have the source code
                } elseif ('user defined' === $this->used_functions[$used_function_index][_PHPI_USER_DEFINED]) {
                    //search for the return value of the function
                    //return a value if the function is a user defined function with a return value
                    //return null if there is no variable
                    if (is_null($variable_index)) {
                        continue;
                    }
                } elseif ('other' === $this->used_functions[$used_function_index][_PHPI_OTHER]) {
                    //search for the return value of the function
                    //return a value if the function is a user defined function with a return value
                    //return null if there is no variable
                    $variable_index = count($this->parser_variables) - 1;
                } elseif ('revert filter' === $this->used_functions[$used_function_index][_PHPI_REVERT_FILTER]) {
                    //search for the return value of the function
                    //return a value if the function is a user defined function with a return value
                    //return null if there is no variable
                    $variable_index = count($this->parser_variables) - 1;

                    // it is a user defined function from which there is no source code
                    // or it is a filter or a revert filter PHP function
                    // or other PHP function
                } else {
                    $variable_index = count($this->parser_variables) - 1;
                    if ($target_function_name != $this->parser_variables[$variable_index][_PHPI_NAME]) {
                        continue;
                    }
                }
            } else {
                //if it is not a variable, property, function, method continue
                continue;
            }

            /*
             * update variable attributes
             *
             */
            //it is a user defined function with a return value
            //if the code is from an output function then the variable is an output variable
            if (OUTPUT_VARIABLE === $output_variable_attribute) {
                $this->parser_variables[$variable_index][_PHPI_OUTPUT] = OUTPUT_VARIABLE;
            }
            //propagate the tainted attribute
            if (TAINTED === $this->parser_variables[$variable_index][_PHPI_TAINTED]) {
                $tainted = TAINTED;
                // if it is also an output variable we have a vulnerability
                if ((OUTPUT_VARIABLE === $output_variable_attribute) && (!is_null($vulnerability_classification))) {
                    //if (( UNKNOWN != $vulnerability_classification) && ('function' === $this->parser_variables[$variable_index]['variable_function']) && ($target_function_name != $this->parser_variables[$variable_index][_PHPI_NAME]) && ('Possible ' != substr($vulnerability_classification, 0, 9))
                    if ((UNKNOWN != $vulnerability_classification) && ('function' === $this->parser_variables[$variable_index][_PHPI_VARIABLE_FUNCTION]) && ($target_function_name != $this->parser_variables[$variable_index][_PHPI_NAME]) && ('Possible ' != substr($vulnerability_classification, 0, 9))
                    ) {
                        $vulnerability_classification = 'Possible ' . $vulnerability_classification;
                    }
                    $this->parser_variables[$variable_index][_PHPI_VULNERABILITY] = $vulnerability_classification;
                }
            }

            $variable_dependencies_index[] = $variable_index;
        }

        if ((is_null($vulnerability_classification)) || (UNTAINTED === $tainted)) {
            $vulnerability_classification = UNKNOWN;
        }

//    echo 'OUTPUT expression $tainted '.$tainted.' $vulnerability_classification '.$vulnerability_classification.' $variable_dependencies_index '.$variable_dependencies_index.'<br />';
        return (array(
            _PHPI_TAINTED => $tainted,
            _PHPI_VULNERABILITY => $vulnerability_classification,
            _PHPI_DEPENDENCIES_INDEX => $variable_dependencies_index,
        ));
    }

    /**
     * The variable at the left side of the '=' sign receives the attributes
     * tainted, vulnerability_classification, variable_dependencies_index of the variable at the right side of the '=' sign
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $variable_before_equal_index with the index of the variable in tokens of the multi-dimensional array $parser_variables
     *
     * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
     */
    // original
//  function parse_equal_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $variable_before_equal_index) {
//    // $this->debug( sprintf( "%s:%s:<b><span style='color:blueviolet;'>%s</span></b> :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );
//
//    if ($this->parser_debug2_flag)
//      $this->debug2("parse_equal_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_before_equal_index )", 'parse_equal_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_before_equal_index )');
//
//
//    $expression = $this->parse_expression_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, null, null);
//
//    //update the atributes of the variable in the left side of the '='
//    $this->parser_variables[$variable_before_equal_index][_PHPI_TAINTED] = $expression[_PHPI_TAINTED];
//    $this->parser_variables[$variable_before_equal_index][_PHPI_VULNERABILITY] = $expression[_PHPI_VULNERABILITY];
//    $this->parser_variables[$variable_before_equal_index][_PHPI_DEPENDENCIES_INDEX] = $expression[_PHPI_DEPENDENCIES_INDEX];
//  }

    function parse_equal_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $variable_before_equal_index)
    {
        // $this->debug( sprintf( "%s:%s:<b><span style='color:blueviolet;'>%s</span></b> :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

        if ($this->parser_debug2_flag)
            $this->debug2("parse_equal_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_before_equal_index )", 'parse_equal_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_before_equal_index )');

        //echo  "<p>parse_equal_vulnerability($file_name, $function_name, $block_start_index, $block_end_index, $variable_before_equal_index)</p>";

        $expression = $this->parse_expression_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, null, null);

        //update the atributes of the variable in the left side of the '='
        $this->parser_variables[$variable_before_equal_index][_PHPI_TAINTED] = $expression[_PHPI_TAINTED];
        $this->parser_variables[$variable_before_equal_index][_PHPI_VULNERABILITY] = $expression[_PHPI_VULNERABILITY];
        $this->parser_variables[$variable_before_equal_index][_PHPI_DEPENDENCIES_INDEX] = $expression[_PHPI_DEPENDENCIES_INDEX];

        // 2015-01-22
        // $o =            new           class_name()
        //       $block_start_index    +1
//    for ($i = $block_start_index; $i <= $block_start_index + 2; $i++) {
//      $t = $this->files->files_tokens[$file_name][$i];
//      if (is_array($t)) {
//        //echo token_name($t[0]) . $t[1] . $t[2] . " $i <br>";
//      } else {
//       // echo $t[0] . " $i <br>";
//      }
//    }
        //echo "<hr>";
        $token = $this->files->files_tokens[$file_name][$block_start_index];
        if (is_array($token)) {
            if ($token[0] === T_NEW) {
                //echo "$block_start_index $token<br/>";
                // The variable name is the object name.
                $this->parser_variables[$variable_before_equal_index][_PHPI_OBJECT] = $this->parser_variables[$variable_before_equal_index][_PHPI_NAME];
                $this->parser_variables[$variable_before_equal_index][_PHPI_CLASS] = $this->files->files_tokens[$file_name][$block_start_index + 1][1];
            }
        }
    }

    /**
     * The variable at the right side of the AS token receives the attributes
     * tainted, vulnerability_classification, variable_dependencies_index of the variable at the left side of the AS token
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param string $function_name with the name of the function where the code is being executed.
     * if the code ise being executed outside any function this argument should take the value 'function', which is the default value.
     * This name was choosen because 'function' is a PHP reserved word, so there won't be any function with that name (which could cause mistakes)
     * @param string $block_start_index with the start index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $block_end_index with the end index of tokens of the multi-dimensional array $files_tokens that is going to be parsed
     * @param string $variable_before_as_index with the index of the variable in tokens of the multi-dimensional array $parser_variables
     *
     * @return int with the index of multi-dimensional associative array $files_tokens with the end of the assignment
     */
    function parse_foreach_vulnerability($file_name, $class_name, $function_name, $block_start_index, $block_end_index, $variable_before_as_index)
    {
        //$this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

        if ($this->parser_debug2_flag)
            $this->debug2("parse_foreach_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_before_as_index )", ' parse_foreach_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_before_as_index )');


        $index = $block_start_index;
        //$index (the $files_tokens index) is passed by reference. When it is a function it returns the vlue 'function'
        //$variable_after_as_name = $this->get_variable_property_complete_array_name($file_name, $index);
        $ra = $this->get_variable_property_complete_array_name($file_name, $index);
        $variable_after_as_name = $ra[0];
        $index = $ra[1];

        //add the variable to the multi-dimensional associative array $parser_variables
        $this->parse_variable_property($file_name, $class_name, $function_name, $block_start_index);

        // $this->get_variable_index return null if there is no variable
        $variable_after_as_index = $this->get_variable_index($file_name, $variable_after_as_name, $function_name);

        if (!is_null($variable_before_as_index)) {
            $this->parser_variables[$variable_after_as_index][_PHPI_TAINTED] = $this->parser_variables[$variable_before_as_index][_PHPI_TAINTED];
            $this->parser_variables[$variable_after_as_index][_PHPI_VULNERABILITY] = $this->parser_variables[$variable_before_as_index][_PHPI_VULNERABILITY];
            $this->parser_variables[$variable_after_as_index][_PHPI_DEPENDENCIES_INDEX][] = $variable_before_as_index;
        } else {
            $this->parser_variables[$variable_after_as_index][_PHPI_TAINTED] = UNTAINTED;
            $this->parser_variables[$variable_after_as_index][_PHPI_VULNERABILITY] = UNKNOWN;
            $this->parser_variables[$variable_after_as_index][_PHPI_DEPENDENCIES_INDEX][] = null;
        }
    }

    /**
     * Extract the variable information from the multi-dimensional array $files_tokens
     * and store it in the multi-dimensional associative array $parser_variables
     * Make a distinction between regular and input variables
     * Taint input variables
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
        //$this->debug( sprintf( "%s:%s:<span style='color:red;'>%s</span> :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

        if ($this->parser_debug2_flag) {
            $this->debug2("parse_variable_property_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_name, $variable_scope, $code_type )", 'parse_variable_property_vulnerability( $file_name, $function_name, $block_start_index, $block_end_index, $variable_name, $variable_scope, $code_type )');
        }


        if (!is_null($variable_name) && ($variable_name != 'function')) {
            //get the variable name even if it is preceded by a '&'
            if ('&' === $this->files->files_tokens[$file_name][$block_start_index]) {
                $block_start_index++;
            }

            $line_number = $this->files->files_tokens[$file_name][$block_start_index][2];

            //regular variables are by default safe
            $output_variable = REGULAR_VARIABLE;

            //regular variables are by default safe
            $input_variable = REGULAR_VARIABLE;
            $tainted = UNTAINTED;
            $short_variable_name = $this->get_variable_property_name($file_name, $block_start_index);
            //search for input vulnerable variables

            foreach (Vulnerable_Input::$INPUT_VARIABLES as $key => $value) {
                //foreach ($INPUT_VARIABLES as $key => $value) {
                //search for PHP reserved variables
                foreach ($value as $input_array_var) {
                    //if it is a PHP reserved variables
                    if ($short_variable_name === $input_array_var) {
                        $input_variable = INPUT_VARIABLE;
                        $tainted = TAINTED;
                        //leave outter foreach
                        break 2;
                    }
                }
            }

            //find if the variable already exists. In this case the variable is updated
            //If the variable is an object and it is tainted, then the contents of that variable are also tainted
            $object_variable_name = $this->get_object_name($variable_name);
            $variable_name_index = $this->get_object_property_index($file_name, $function_name, $variable_name);

            // if it is a variable process it. Otherwise leave this function
            if (!is_null($variable_name_index)) {
                //If the variable already exists in the scope and is tainted, then this should be reflected in the current usage of the variable
                if (TAINTED === $this->parser_variables[$variable_name_index][_PHPI_TAINTED]) {
                    $tainted = TAINTED;
                }
                $variable_scope = $this->parser_variables[$variable_name_index][_PHPI_SCOPE];
            }
            if ((is_null($variable_name_index)) || ((!is_null($variable_name_index)) && (($this->parser_variables[$variable_name_index][_PHPI_START_INDEX] != $block_start_index) && ($this->parser_variables[$variable_name_index][_PHPI_END_INDEX] != $block_end_index)))) {

							// 2016-11-27, SS
							$previous_containing_function = $this->find_previous_containing_function_from_index($file_name, $block_start_index);
							//echo $previous_containing_function;
							// 2016-11-27, SS
						
                //add the variable name, variable used in PHP or outside PHP, input variable?, the function name, the file name and the line number and the taint value, variable classification, and the $parserFileTokens array index
                $this->parser_variables[] = array(
                    _PHPI_NAME => $variable_name,
                    _PHPI_OBJECT => $object_variable_name,
                    _PHPI_CLASS => null,
                    _PHPI_SCOPE => $variable_scope,
                    _PHPI_VARIABLE_FUNCTION => 'variable',
                    _PHPI_EXIST_DESTROYED => EXIST,
                    _PHPI_CODE_TYPE => $code_type,
                    _PHPI_INPUT => $input_variable,
                    _PHPI_OUTPUT => $output_variable,
                    _PHPI_FUNCTION => $function_name,
                    _PHPI_FILE => $file_name,
                    _PHPI_LINE => $line_number,
                    _PHPI_TAINTED => $tainted,
                    _PHPI_VULNERABILITY => UNKNOWN,
                    _PHPI_START_INDEX => $block_start_index,
                    _PHPI_END_INDEX => $block_end_index,
                    _PHPI_DEPENDENCIES_INDEX => null,
                    _PHPI_VARIABLE_FILTER => null,
                    _PHPI_VARIABLE_REVERT_FILTER => null,
										_PHPI_SENSITIVE_SINK => $previous_containing_function,
										_PHPI_SENSITIVE_SINK_VULNERABILITY => $this->getFunctionVulnType($previous_containing_function)
                );

                // Change, add. Parallel array
                // if not exists, 4nd key '0' else n+1
                $fln = $file_name;
                $vn = $variable_name;
                $fn = $function_name;
                $this->add_parser_variables_lookup($fln, $vn, $fn, count($this->parser_variables) - 1);
                //To.
            }

            //If the variable already exists in the scope the new variable depends on it and it is not in the same PHP line
            if ((!is_null($variable_name_index)) && ($this->start_of_php_line($file_name, $block_start_index) > $this->start_of_php_line($file_name, $this->parser_variables[$variable_name_index][_PHPI_END_INDEX]))) {
                $newVariableNameIndex = $this->get_variable_index($file_name, $variable_name, $function_name);
                //do not add a dependency if it already exists
                $match = false;
                if (is_array($this->parser_variables[$newVariableNameIndex][_PHPI_DEPENDENCIES_INDEX])) {
                    foreach ($this->parser_variables[$newVariableNameIndex][_PHPI_DEPENDENCIES_INDEX] as $key => $value) {
                        if ($variable_name_index === $value) {
                            $match = true;
                            break;
                        }
                    }
                }
                if (false === $match) {
                    $this->parser_variables[$newVariableNameIndex][_PHPI_DEPENDENCIES_INDEX][] = $variable_name_index;
                }
            }

            //if the variable is used as a single code (maybe inside HTML code) and is tainted, then we may have a vulnerability
            if (TAINTED === $tainted) {

                $variable_name_index = $this->get_variable_index($file_name, $variable_name, $function_name);
                //obtain the line of code where the variable is located
                $start_of_php_line_index = $this->start_of_php_line($file_name, $block_start_index);
                $end_of_php_line_index = $this->end_of_php_line($file_name, $block_start_index);

                //if the start and the end of the line are PHP_OPEN_TAG and PH_CLOSE_TAG
                if (((T_OPEN_TAG === $this->files->files_tokens[$file_name][$start_of_php_line_index][0]) || (T_OPEN_TAG_WITH_ECHO === $this->files->files_tokens[$file_name][$start_of_php_line_index][0])) && (T_CLOSE_TAG === $this->files->files_tokens[$file_name][$end_of_php_line_index][0])) {
                    $is_single_code = true;
                    for ($i = $start_of_php_line_index; $i < $end_of_php_line_index; $i++) {
                        $token = $this->files->files_tokens[$file_name][$i][0];
                        //it is considered as a single code if it has no loops nor conditional structures
                        if ((T_FOR === $token) || (T_FOREACH === $token) || (T_DO === $token) || (T_WHILE === $token) || (T_ENDWHILE === $token) || (T_ELSEIF === $token) || (T_ELSE === $token) || (T_IF === $token) || (T_SWITCH === $token) || ('=' === $this->files->files_tokens[$file_name][$i])) {
                            $is_single_code = false;
                            break;
                        }
                    }

                    //vulnerabilityClassification is XSS
                    if (true === $is_single_code) {
                        //it only considered when the variable is not part of a function
                        $previous_containing_function = $this->find_previous_containing_function_from_index($file_name, $block_start_index);
                        if (is_null($previous_containing_function)) {
                            if (TAINTED === $this->parser_variables[$variable_name_index][_PHPI_TAINTED]) {
                                $this->parser_variables[$variable_name_index][_PHPI_VULNERABILITY] = XSS;
                            }
                            $this->parser_variables[$variable_name_index][_PHPI_OUTPUT] = OUTPUT_VARIABLE;
                        }
                    }
                }
            }
        }
    }

    /**
     * Parse unset.
     * When the variable is unset, PHP destroys the variable.
     * For the vulnerability detection it is the same as being UNTAINTED
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
        //$this->debug( sprintf( "%s:%s:%s :: %s", __CLASS__, __METHOD__, __FUNCTION__, serialize( func_get_args() ) ) . '<br />' );

        if ($this->parser_debug2_flag)
            $this->debug2("parse_unset_vulnerability( $block_end_index, $variable_index )", 'parse_unset_vulnerability( $block_end_index, $variable_index )');

        $this->parser_variables[$variable_index][_PHPI_TAINTED] = UNTAINTED;
        $this->parser_variables[$variable_index][_PHPI_EXIST_DESTROYED] = DESTROYED;
        $this->parser_variables[$variable_index][_PHPI_VULNERABILITY] = UNKNOWN;
    }

    /**
     * Get the protections of the variable that is an argument of a function, by order of appearence
     *
     * TODO allowing more stuff than just function1(function2(var))
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param int $block_end_index with the index of the variable in the multi-dimensional array $files_tokens
     *
     * @return array of the name of the filtering functions
     */
    function get_variable_filters($file_name, $block_end_index)
    {
        $variable_protection_functions = null;
        $i = $block_end_index - 1;
        do {
            if ('(' === $this->files->files_tokens[$file_name][$i]) {
                $i--;
                continue;
            }
            if (is_array($this->files->files_tokens[$file_name][$i])) {
                if (T_STRING === $this->files->files_tokens[$file_name][$i][0]) {
                    $found_variable_filter = false;
                    //test if it is one of the filtering functions
                    $function_name = $this->files->files_tokens[$file_name][$i][1];
                    foreach (Vulnerable_Filter::$VARIABLE_FILTERS as $key => $value) {
                        foreach ($value as $output) {
                            //note: PHP functions are not case sensitive
                            if (0 === strcasecmp($output, $function_name)) {
                                $variable_protection_functions[] = $output;
                                $found_variable_filter = true;
                                //leave outter foreach
                                break 2;
                            }
                        }
                    }
                } else {
                    return $variable_protection_functions;
                }
            }
            $i--;
        } while ($i > 0);
        return $variable_protection_functions;
    }

    /**
     * Get the protections and the revert protections of the variable that is an argument of a function, by order of appearence
     *
     * TODO allowing more stuff than just function1(function2(var))
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param int $block_end_index with the index of the variable in the multi-dimensional array $files_tokens
     *
     * @return array of the name of the filtering functions
     */
    function get_variable_filters_and_revert_filters($file_name, $block_end_index)
    {

        $variable_protection_functions = null;
        $previous_containing_function = $this->find_previous_containing_function_from_index($file_name, $block_end_index);
        if (!is_null($previous_containing_function)) {
            $found_variable_filter = false;
            foreach (array_merge(Vulnerable_Filter::$VARIABLE_FILTERS, Vulnerable_Filter::$REVERT_VARIABLE_FILTERS) as $key => $value) {
                foreach ($value as $output) {
                    //note: PHP functions are not case sensitive
                    if (0 === strcasecmp($output, $previous_containing_function)) {
                        $variable_protection_functions = $output;
                        $found_variable_filter = true;
                        break 2;
                    }
                }
            }
        }
        return $variable_protection_functions;
    }

    /**
     * Check if the variable that is an argument of a function is being protected by that function
     *
     * TODO allowing more stuff than just function1(function2(var))
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param int $block_end_index with the index of the variable in the multi-dimensional array $files_tokens
     *
     * @return bool true if the variable is protected and false if the variable is not protected
     */
    function is_variable_filtered($file_name, $block_end_index)
    {
        $previous_containing_function = $this->find_previous_containing_function_from_index($file_name, $block_end_index);
        if (!is_null($previous_containing_function)) {
            foreach (Vulnerable_Filter::$VARIABLE_FILTERS as $key => $value) {
                foreach ($value as $output) {
                    //note: PHP functions are not case sensitive
                    if (0 === strcasecmp($output, $previous_containing_function)) {
                        return $output;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Get the protections of the variable that is an argument of a function, by order of appearence
     *
     * TODO allowing more stuff than just function1(function2(var))
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param int $block_end_index with the index of the variable in the multi-dimensional array $files_tokens
     *
     * @return array of the name of the filtering functions
     */
    function get_variable_revert_filters($file_name, $block_end_index)
    {
        $variable_protection_functions = null;
        $i = $block_end_index - 1;
        do {
            if ('(' === $this->files->files_tokens[$file_name][$i]) {
                $i--;
                continue;
            }
            if (is_array($this->files->files_tokens[$file_name][$i])) {
                if (T_STRING === $this->files->files_tokens[$file_name][$i][0]) {
                    $found_variable_filter = false;
                    //test if it is one of the filtering functions
                    $function_name = $this->files->files_tokens[$file_name][$i][1];
                    foreach (Vulnerable_Filter::$REVERT_VARIABLE_FILTERS as $key => $value) {
                        foreach ($value as $output) {
                            //note: PHP functions are not case sensitive
                            if (0 === strcasecmp($output, $function_name)) {
                                $variable_protection_functions[] = $output;
                                $found_variable_filter = true;
                                break 2;
                            }
                        }
                    }
                } else {
                    return $variable_protection_functions;
                }
            }
            $i--;
        } while ($i > 0);
        return $variable_protection_functions;
    }

    /**
     * Check if the variable that is an argument of a function is being protected by that function
     *
     * TODO allowing more stuff than just function1(function2(var))
     *
     * @param string $file_name with the PHP file name that is going to be parsed
     * @param int $block_end_index with the index of the variable in the multi-dimensional array $files_tokens
     *
     * @return bool true if the variable is protected and false if the variable is not protected
     */
    function is_variable_revert_filtered($file_name, $block_end_index)
    {
        $i = $block_end_index - 1;
        do {
            if ('(' === $this->files->files_tokens[$file_name][$i]) {
                $i--;
                continue;
            }
            if (is_array($this->files->files_tokens[$file_name][$i])) {
                if (T_STRING === $this->files->files_tokens[$file_name][$i][0]) {
                    //test if it is one of the filtering functions
                    $function_name = $this->files->files_tokens[$file_name][$i][1];
                    foreach (Vulnerable_Filter::$REVERT_VARIABLE_FILTERS as $key => $value) {
                        foreach ($value as $output) {
                            //note: PHP functions are not case sensitive
                            if (0 === strcasecmp($output, $function_name)) {
                                return true;
                            }
                        }
                    }
                } else
                    return false;
            }
            $i--;
        } while ($i > 0);
        return false;
    }

    /**
     * creates the multi-dimensional associative array with the PHP vulnerable variables
     * change: 2016-04-19
     */
    function set_vulnerable_variables()
    {
        $this->vulnerable_variables = array();
        for ($i = 0, $count_parser_variables = count($this->parser_variables); $i < $count_parser_variables; $i++) {

            //remove duplicate vulnerable variables
            $exist = false;
            for ($j = 0, $count_vulnerable_variables = count($this->vulnerable_variables); $j < $count_vulnerable_variables; $j++) {
                if (($this->parser_variables[$i][_PHPI_NAME] === $this->vulnerable_variables[$j][_PHPI_NAME])
                    && ($this->parser_variables[$i][_PHPI_FILE] === $this->vulnerable_variables[$j][_PHPI_FILE])
                    && ($this->parser_variables[$i][_PHPI_LINE] === $this->vulnerable_variables[$j][_PHPI_LINE])
                    //  && ($this->parser_variables[$i][_PHPI_END_INDEX] === $this->vulnerable_variables[$j][_PHPI_END_INDEX])
                    //    && ($this->parser_variables[$i][_PHPI_START_INDEX] === $this->vulnerable_variables[$j][_PHPI_START_INDEX])
                ) {
                    $exist = true;
                    break;
                }
            }
            if ($exist === true) {
                continue;
            }

            $variable = $this->parser_variables[$i];
            if ((UNKNOWN != $variable[_PHPI_VULNERABILITY]) && (FILTERED != $variable[_PHPI_VULNERABILITY])) {
                //add $parser_variables index
                $parser_variables_with_index = array_merge(array(_PHPI_INDEX => $i), $this->parser_variables[$i]);
                $this->vulnerable_variables[] = $parser_variables_with_index;
            }
        }
        // echo "<h1>XZS " .  count($this->vulnerable_variables) . "</h1>";
    }

    /**
     * creates the multi-dimensional associative array with the PHP output variables
     */
    function set_output_variables()
    {
        $this->output_variables = array();
        for ($i = 0, $count = count($this->parser_variables); $i < $count; $i++) {
            $variable = $this->parser_variables[$i];
            if ((OUTPUT_VARIABLE === $variable[_PHPI_OUTPUT])) {
                //add $parser_variables index
//        foreach ($variable as $key => $value) {
//          echo "$key $value<br>";
//        }
                $parser_variables_with_index = array_merge(array(_PHPI_INDEX => $i), $this->parser_variables[$i]);
                $this->output_variables[] = $parser_variables_with_index;
            }
        }
    }


    /**
     * creates the multi-dimensional associative array with the PHP non-vulnerable-variables (i.e., output variables that depend of user input)
     */
    function set_non_vulnerable_variables()
    {
        $this->non_vulnerable_variables = array();
        for ($i = 0, $count_parser_variables = count($this->parser_variables); $i < $count_parser_variables; $i++) {

            //remove duplicate vulnerable variables
            $exist = false;
            for ($j = 0, $count_non_vulnerable_variables = count($this->non_vulnerable_variables); $j < $count_non_vulnerable_variables; $j++) {
                if (($this->parser_variables[$i][_PHPI_NAME] === $this->non_vulnerable_variables[$j][_PHPI_NAME])
                    && ($this->parser_variables[$i][_PHPI_FILE] === $this->non_vulnerable_variables[$j][_PHPI_FILE])
                    && ($this->parser_variables[$i][_PHPI_LINE] === $this->non_vulnerable_variables[$j][_PHPI_LINE])
                    //  && ($this->parser_variables[$i][_PHPI_END_INDEX] === $this->vulnerable_variables[$j][_PHPI_END_INDEX])
                    //    && ($this->parser_variables[$i][_PHPI_START_INDEX] === $this->vulnerable_variables[$j][_PHPI_START_INDEX])
                ) {
                    $exist = true;
                    break;
                }
            }
            if ($exist === true) {
                continue;
            }

            //$this->parser_variables[$k][_PHPI_TAINTED] = $tainted;
            //$this->parser_variables[$k][_PHPI_VULNERABILITY] = $vul;   // filtered
            $variable = $this->parser_variables[$i];
            if ((OUTPUT_VARIABLE === $variable[_PHPI_OUTPUT])
                //    && ('untainted' === $variable[_PHPI_TAINTED]) || (1==1)
            ) {
                //if ((UNKNOWN == $variable[_PHPI_VULNERABILITY] ) || (FILTERED == $variable[_PHPI_VULNERABILITY] )) {
                //if ((UNKNOWN != $variable[_PHPI_VULNERABILITY] ) && (FILTERED != $variable[_PHPI_VULNERABILITY] )) {
                //add $parser_variables index
                $parser_variables_with_index = array_merge(array(_PHPI_INDEX => $i), $this->parser_variables[$i]);
                $this->non_vulnerable_variables[] = $parser_variables_with_index;
            }
        }
    }

    /**
     * gets the multi-dimensional associative array with the PHP vulnerable variable attributes
     *
     * @return the multi-dimensional associative array vulnerableVariables
     */
    function get_vulnerable_variables()
    {
        return $this->vulnerable_variables;
    }

    /**
     * gets the multi-dimensional associative array with the PHP vulnerable variable attributes
     *
     * @return the multi-dimensional associative array vulnerableVariables
     */
    function get_non_vulnerable_variables()
    {
        return $this->non_vulnerable_variables;
    }

    /**
     * gets the multi-dimensional associative array with the PHP output variable attributes
     *
     * @return the multi-dimensional associative array outputVariables
     */
    function get_output_variables()
    {
        return $this->output_variables;
    }

}

// The ending PHP tag is omitted. This is actually safer than including it.