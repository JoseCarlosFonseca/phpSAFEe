<?php
/*
Plugin Name: Couponer
Plugin URI: http://couponer.zyphon-media.net
Description: An easy-to-use plugin that allows you to make simple coupons.
Version: 1.2
Author: Christopher Choma
Author URI: http://chrischoma.com
License: GPL2
*/
?>
<?php
if (!class_exists("Couponer")) {
	class Couponer {
		function Couponer() { //constructor
		
			global $couponer_db_version;
			$couponerl_db_version = "1.0";
			
			function couponer_install () {
			   global $wpdb;
			   global $couponer_db_version;
			   
				$logo = get_bloginfo('url') . '/wp-content/plugins/couponer/images/logo60x30.gif';
				add_option('Couponer_Logo', $logo);
			
			   $table_name = $wpdb->prefix . "couponer";
			   if($wpdb->get_var("show tables like '$table_name'") != $table_name) {
			      
			      $sql = "CREATE TABLE " . $table_name . " (
				  ID INT NOT NULL AUTO_INCREMENT PRIMARY KEY ,
				  Title TEXT NOT NULL ,
				  Description TEXT NOT NULL ,
				  Terms TEXT NOT NULL ,
				  Expires DATE NOT NULL ,
				  Created TIMESTAMP NOT NULL ,
				  Image VARCHAR( 500 ) NOT NULL ,
				  Active ENUM(  '0',  '1' ) DEFAULT '1' NOT NULL
				  
				);";
			
			      require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
			      dbDelta($sql);
			
			      $rows_affected = $wpdb->insert( $table_name, array( 'time' => current_time('mysql'), 'name' => $welcome_name, 'text' => $welcome_text ) );
			 
			      add_option("couponer_db_version", $couponer_db_version);
			
			   }
			}

			register_activation_hook(__FILE__,'couponer_install');


			add_action('admin_menu', 'couponer_menu');

				function couponer_menu() {
					add_options_page('Couponer Options', 'Couponer', 'manage_options', 'couponer', 'couponer_options');
				}
				
				function couponer_options() {
					if (!current_user_can('manage_options'))  {
						wp_die( __('You do not have sufficient permissions to access this page.') );
					}
					echo '<div class="wrap">';
				?>
					<div id="couponer_container">
						<table cellpadding="0" cellspacing="15" width="100%" class="widefat">
							<tr>
								<td>
									<div id="create" style="width:75%;float:left;">
										<h2>Create a New Coupon</h2>
										<form action="<?php bloginfo('url'); ?>/wp-content/plugins/couponer/add-coupon.php" method="post">
											<table>
												<tr>
													<td class="label" style="border:0;">Title:</td>
													<td style="border:0;"><input type="text" name="Title" style="width:400px" /></td>
												</tr>
												<tr>
													<td class="label" style="border:0;">Description:</td>
													<td style="border:0;"><input type="text" name="Description" style="width:400px" /></td>
												</tr>
												<tr>
													<td class="label" style="border:0;">Terms:</td>
													<td style="border:0;"><input type="text" name="Terms" style="width:400px" /></td>
												</tr>
												<tr>
													<td class="label" style="border:0;">Expires:</td>
													<td style="border:0;">
														<select name="Exp-M">
															<option value=""></option>
															<option value="01">01 - Jan</option>
															<option value="02">02 - Feb</option>
															<option value="03">03 - Mar</option>
															<option value="04">04 - Apr</option>
															<option value="05">05 - May</option>
															<option value="06">06 - Jun</option>
															<option value="07">07 - July</option>
															<option value="08">08 - Aug</option>
															<option value="09">09 - Sept</option>
															<option value="10">10 - Oct</option>
															<option value="11">11 - Nov</option>
															<option value="12">12 - Dec</option>
														</select> - 
														<select name="Exp-D">
															<option value=""></option>
															<option value="01">01</option>
															<option value="02">02</option>
															<option value="03">03</option>
															<option value="04">04</option>
															<option value="05">05</option>
															<option value="06">06</option>
															<option value="07">07</option>
															<option value="08">08</option>
															<option value="09">09</option>
															<option value="10">10</option>
															<option value="11">11</option>
															<option value="12">12</option>
															<option value="13">13</option>
															<option value="14">14</option>
															<option value="15">15</option>
															<option value="16">16</option>
															<option value="17">17</option>
															<option value="18">18</option>
															<option value="19">19</option>
															<option value="20">20</option>
															<option value="21">21</option>
															<option value="22">22</option>
															<option value="23">23</option>
															<option value="24">24</option>
															<option value="25">25</option>
															<option value="26">26</option>
															<option value="27">27</option>
															<option value="28">28</option>
															<option value="29">29</option>
															<option value="30">30</option>
															<option value="31">31</option>
														</select> - 
														<select name="Exp-Y">
															<option value=""></option>
															<option value="2011">2011</option>
															<option value="2012">2012</option>
															<option value="2013">2013</option>
															<option value="2014">2014</option>
															<option value="2015">2015</option>
															<option value="2016">2016</option>
															<option value="2017">2017</option>
															<option value="2018">2018</option>
															<option value="2019">2019</option>
															<option value="2020">2020</option>
														</select>
														
														</td>
												</tr>
												<tr>
													<td class="label" style="border:0;">Image URL:</td>
													<td style="border:0;"><input type="text" name="Image" style="width:400px" /> <em style="font-size:10px;">Resize images to less than 90x90 pixels for best performance and appearance.</em></td>
												</tr>
												<tr>
													<td class="label" style="border:0;"></td>
													<td style="border:0;"><input type="submit" value="Create Coupon" /></td>
												</tr>
											</table>
										</form>
									</div>
								</td>
								<td width="350px" style="padding-right:50px;">
						
									<div id="settings">
										<h2>Settings</h2>
										<div style="float:left;background:#F9F9F9;border:2px solid #DFDFDF;padding:10px;">
											<strong>Footer Logo</strong><br />
											<img src="<?php echo get_option('Couponer_Logo'); ?>" alt="<?php echo get_option('Couponer_Logo'); ?>" />
											<br /><br />
											<strong>Replace Logo</strong> (Enter New URL)<br />
											<form method="post" action="<?php bloginfo('url'); ?>/wp-content/plugins/couponer/process-coupon.php?mode=couponerlogo">
												<input type="text" name="Couponer_Logo" style="width:220px" />
												<input type="submit" value="Submit" /><br />
												<em style="font-size:10px;">Resize image to less than 60x30 pixels for best performance and appearance.</em>
											</form>
										</div>
									</div>
								</td>
							</tr>
						</table>
						<div id="current" style="float:left;clear:both;">
							<h2>Saved Coupons</h2>
							<h3>Active Coupons</h3>
							<table cellpadding="0" cellspacing="15" width="100%" class="widefat">
								<thead>
									<tr>
										<th></th>
										<th>ID</th>
										<th>Title</th>
										<th>Description</th>
										<th>Terms</th>
										<th>Expires</th>
										<th>Created</th>
										<th>Action</th>
									</tr>
								</thead>
								<tbody>
							<?php 
								$sql_get_coupon_active = "SELECT *, DATE_FORMAT(Expires, '%b %e, %Y') as Expires, DATE_FORMAT(Created, '%b %e, %Y') as Created FROM wp_couponer WHERE Active='1'";
								$result_get_coupon_active = mysql_query($sql_get_coupon_active);
								if (!$result_get_coupon_active) {
								    echo '<tr><td colspan="7">Could not successfully run query ($sql_get_coupon_active) from DB: </strong>" . mysql_error()."</td></tr>';
								}
								if (mysql_num_rows($result_get_coupon_active) == 0) {
									echo '<tr><td colspan="7">You do not have any active coupons.</td></tr>';
								}
								while ($row_get_coupon_active = mysql_fetch_assoc($result_get_coupon_active)) {
								
									$check_exp = "SELECT *, DATE_FORMAT(Expires, '%b %e, %Y') as Expires FROM wp_couponer WHERE Expires<=CURDATE()";
									$result_get_coupon_exp = mysql_query($check_exp);
									$row_exp = mysql_fetch_assoc($result_get_coupon_exp);
								?>
									<tr>
										<td><img src="<?php echo $row_get_coupon_active['Image']; ?>" style="max-width:90px;max-height:90px;" /></td>
										<td><?php echo $row_get_coupon_active['ID']; ?></td>
										<td><?php echo $row_get_coupon_active['Title']; ?></td>
										<td><?php echo $row_get_coupon_active['Description']; ?></td>
										<td><?php echo $row_get_coupon_active['Terms']; ?></td>
										<td<?php if ($row_exp['Expires']==$row_get_coupon_active['Expires']) { echo ' style="font-weight:bold;color:#d90000;"'; } ?>><?php echo $row_get_coupon_active['Expires']; ?></td>
										<td><?php echo $row_get_coupon_active['Created']; ?></td>
										<td><a href="<?php bloginfo('url'); ?>/wp-content/plugins/couponer/process-coupon.php?mode=deactivate&ID=<?php echo $row_get_coupon_active['ID']; ?>">Deactivate</a> | <a onclick="deleteActive()" href="#">Delete</a></td>
									</tr>
									<script type="text/javascript">
									<!--
									function deleteActive() {
										var answer = confirm("Delete Coupon?")
										if (answer){
											window.location = "<?php bloginfo('url'); ?>/wp-content/plugins/couponer/process-coupon.php?mode=delete&ID=<?php echo $row_get_coupon_active['ID']; ?>";
										}
										else{
											
										}
									}
									//-->
									</script>
								<?php
									}
								mysql_free_result($result_get_coupon_active);
							?>
								</tbody>
							</table>
							<br /><br />
							<h3>Inactive Coupons</h3>
							<table cellpadding="0" cellspacing="15" width="100%" class="widefat">
								<thead>
									<tr>
										<th></th>
										<th>ID</th>
										<th>Title</th>
										<th>Description</th>
										<th>Terms</th>
										<th>Expires</th>
										<th>Created</th>
										<th>Action</th>
									</tr>
								</thead>
								<tbody>
							<?php 
								$sql_get_coupon_active = "SELECT *, DATE_FORMAT(Expires, '%b %e, %Y') as Expires, DATE_FORMAT(Created, '%b %e, %Y') as Created FROM wp_couponer WHERE Active='0'";
								$result_get_coupon_active = mysql_query($sql_get_coupon_active);
								if (!$result_get_coupon_active) {
								   echo '<tr><td colspan="7">Could not successfully run query ($sql_get_coupon_active) from DB: </strong>" . mysql_error()."</td></tr>';
								}
								if (mysql_num_rows($result_get_coupon_active) == 0) {
									echo '<tr><td colspan="7">You do not have any inactive coupons.</td></tr>';
								}
								
								while ($row_get_coupon_active = mysql_fetch_assoc($result_get_coupon_active)) {
									
									$check_exp = "SELECT *, DATE_FORMAT(Expires, '%b %e, %Y') as Expires FROM wp_couponer WHERE Expires<=CURDATE()";
									$result_get_coupon_exp = mysql_query($check_exp);
									$row_exp = mysql_fetch_assoc($result_get_coupon_exp);
									
								?>
									<tr>
										<td><img src="<?php echo $row_get_coupon_active['Image']; ?>" style="max-width:90px;max-height:90px;" /></td>
										<td><?php echo $row_get_coupon_active['ID']; ?></td>
										<td><?php echo $row_get_coupon_active['Title']; ?></td>
										<td><?php echo $row_get_coupon_active['Description']; ?></td>
										<td><?php echo $row_get_coupon_active['Terms']; ?></td>
										<td<?php if ($row_exp['Expires']==$row_get_coupon_active['Expires']) { echo ' style="font-weight:bold;color:#d90000;"'; } ?>><?php echo $row_get_coupon_active['Expires']; ?></td>
										<td><?php echo $row_get_coupon_active['Created']; ?></td>
										<td><a href="<?php bloginfo('url'); ?>/wp-content/plugins/couponer/process-coupon.php?mode=activate&ID=<?php echo $row_get_coupon_active['ID']; ?>">Activate</a> | <a onclick="deleteInactive()" href="#">Delete</a></td>
									</tr>
									<script type="text/javascript">
									<!--
									function deleteInactive() {
										var answer = confirm("Delete Coupon?")
										if (answer){
											window.location = "<?php bloginfo('url'); ?>/wp-content/plugins/couponer/process-coupon.php?mode=delete&ID=<?php echo $row_get_coupon_active['ID']; ?>";
										}
										else{
											
										}
									}
									//-->
									</script>
								<?php
									}
								mysql_free_result($result_get_coupon_active);
							?>
								</tbody>
							</table>
						</div>
					</div>
					

				<?php
					echo '</div>';
				}

		}
		
	}
	
	function display_coupons() {

		echo '<link type="text/css" rel="stylesheet" href="' . get_bloginfo('url') . '/wp-content/plugins/couponer/couponer.css" />' . "\n";

		echo '<div id="coupon_container">';
	
		$sql_get_coupon_active = "SELECT *, DATE_FORMAT(Expires, '%b %e, %Y') as Expires, DATE_FORMAT(Created, '%b %e, %Y') as Created FROM wp_couponer WHERE Active='1'";
		$result_get_coupon_active = mysql_query($sql_get_coupon_active);
		if (!$result_get_coupon_active) {
		    echo 'Could not successfully run query ($sql_get_coupon_active) from DB: </strong>" . mysql_error()." ';
		}
		if (mysql_num_rows($result_get_coupon_active) == 0) {
			echo 'There are currently no active coupons. Please check back later.';
		}
		while ($row_get_coupon_active = mysql_fetch_assoc($result_get_coupon_active)) {
		?>

			
			<div class="coupon">
				<div class="box">
					<table>
						<tbody>
							<tr>
								<td valign="middle" class="coupon_title" colspan="2">
									<?php echo $row_get_coupon_active['Title']; ?>
								</td>
							</tr>
							<tr>
								<td class="coupon_desc">
									<?php echo $row_get_coupon_active['Description']; ?>
								</td>
								<td class="coupon_img">
									<img src="<?php echo $row_get_coupon_active['Image']; ?>" />
								</td>
							</tr>
							<tr>
								<td class="coupon_footer" colspan="2">
									<img src="<?php echo get_option('Couponer_Logo'); ?>" alt="<?php echo bloginfo('name'); ?>" />
									*&nbsp;<?php echo $row_get_coupon_active['Terms']; ?>&nbsp;ID# <?php echo $row_get_coupon_active['ID']; ?>&nbsp;Exp. <?php echo $row_get_coupon_active['Expires']; ?>
								</td>
							</tr>
						</tbody>
					</table>
				</div>
				<div class="print">
					<a class="print_link" onclick="javascript:openwin('<?php bloginfo('url'); ?>/wp-content/plugins/couponer/print-coupon.php?ID=<?php echo $row_get_coupon_active['ID']; ?>',400,300);return true;">Print This Coupon</a>
				</div>
			</div>
	<?php
	
	
			}
	?>
			<script type = "text/javascript">
				var popWin = "";
				function openwin(url, strWidth, strHeight) {
				if (popWin != "") {popWin.close()}
				leftStr = (screen.width-strWidth)/2;
				topStr = (screen.height-strHeight)/2-50;
				windowProperties = "location=no,toolbar=yes,menubar=yes,scrollbars=no,statusbar=yes,height="+strHeight+",width="+strWidth+",left="+leftStr+",top="+topStr+"";
				popWin = window.open(url,'newWin',windowProperties);
				}
			</script>
	<?php
	mysql_free_result($result_get_coupon_active);
	echo '</div>';
	
	}
	
} //End Class Couponer

add_shortcode( 'display_coupons', 'display_coupons' );

if (class_exists("Couponer")) {
	$dl_pluginSeries = new Couponer();
}
//Actions and Filters	
if (isset($dl_pluginSeries)) {
	//Actions
	
	//Filters
}
?>
