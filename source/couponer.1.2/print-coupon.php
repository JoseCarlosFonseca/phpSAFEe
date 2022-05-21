<?php 

require_once("../../../wp-config.php");
global $wpdb;

$ID = $_GET['ID'];
		echo '<link type="text/css" rel="stylesheet" href="' . get_bloginfo('url') . '/wp-content/plugins/couponer/couponer.css" />';
		
		$sql_get_coupon_id = "SELECT *, DATE_FORMAT(Expires, '%b %e, %Y') as Expires, DATE_FORMAT(Created, '%b %e, %Y') as Created FROM wp_couponer WHERE ID='$ID'";
		$result_get_coupon_id = mysql_query($sql_get_coupon_id);
		if (!$result_get_coupon_id) {
		    echo '<tr><td colspan="7">Could not successfully run query ($sql_get_coupon_id) from DB: </strong>" . mysql_error()."</td></tr>';
		}
		if (mysql_num_rows($result_get_coupon_id) == 0) {
			echo '<tr><td colspan="7">You do not have any active coupons.</td></tr>';
		}
		while ($row_get_coupon_id = mysql_fetch_assoc($result_get_coupon_id)) {
?>
			<div class="coupon print_coupon">
				<div class="box print_box">
					<table>
						<tbody>
							<tr>
								<td valign="middle" class="coupon_title" colspan="2">
									<h4><?php echo $row_get_coupon_id['Title']; ?></h4>
								</td>
							</tr>
							<tr>
								<td class="coupon_desc">
									<?php echo $row_get_coupon_id['Description']; ?>
								</td>
								<td class="coupon_img">
									<img src="<?php echo $row_get_coupon_id['Image']; ?>" />
								</td>
							</tr>
							<tr>
								<td class="coupon_footer" colspan="2">
									<img src="<?php echo get_option('Couponer_Logo'); ?>" alt="<?php echo bloginfo('name'); ?>" />
									* <?php echo $row_get_coupon_id['Terms']; ?>
									<br>
									ID# <?php echo $row_get_coupon_id['ID']; ?> Exp. <?php echo $row_get_coupon_id['Expires']; ?>
								</td>
							</tr>
						</tbody>
					</table>
				</div>
			</div>
<?php
	}
	mysql_free_result($result_get_coupon_id);
?>
<script type="text/javascript">
	print();
</script>