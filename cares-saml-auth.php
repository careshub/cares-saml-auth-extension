<?php
/**
 * @package Cares_Saml_Auth
 * @wordpress-plugin
 * Plugin Name:       CARES SAML Auth Extension
 * Version:           1.3.0
 * Description:       Extends the SAML authentication plugin for WordPress, using SimpleSAMLphp.
 * Author:            dcavins
 * Text Domain:       cares-saml-auth
 * Domain Path:       /languages
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * GitHub Plugin URI: https://github.com/careshub/cares-saml-auth
 * @copyright 2017 CARES, University of Missouri
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/*----------------------------------------------------------------------------*
 * Public-Facing Functionality
 *----------------------------------------------------------------------------*/

function cares_saml_class_init() {

	$basepath = plugin_dir_path( __FILE__ );

	// Helper functions
	require_once( $basepath . 'includes/functions.php' );

	// The main class
	require_once( $basepath . 'public/class-cares-saml-public.php' );
	$public_class = new CARES_SAML_Public();
	$public_class->add_hooks();

	// Admin and dashboard functionality
	if ( is_admin() && ( ! defined( 'DOING_AJAX' ) || ! DOING_AJAX ) ) {
		require_once( $basepath . 'admin/class-cares-saml-admin.php' );
		$admin_class = new CARES_SAML_Admin();
		$admin_class->add_hooks();
	}

}
add_action( 'init', 'cares_saml_class_init' );


/**
 * Helper function.
 * @return Fully-qualified URI to the root of the plugin.
 */
function cares_saml_get_plugin_base_uri() {
	return plugin_dir_url( __FILE__ );
}

/**
 * Helper function.
 * @return Fully-qualified URI to the root of the plugin.
 */
function cares_saml_get_plugin_base_path() {
	return trailingslashit( dirname( __FILE__ ) );
}

/**
 * Helper function.
 * @TODO: Update this when you update the plugin's version above.
 *
 * @return string Current version of plugin.
 */
function cares_saml_get_plugin_version() {
	return '1.2.0';
}
