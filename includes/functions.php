<?php
/**
 * Utility functions for the plugin.
 *
 * @package   Cares_Saml_Auth
 * @author    dcavins
 * @license   GPL-2.0+
 * @link      http://www.communitycommons.org
 * @copyright 2017 CARES, University of Missouri
 */

/**
 * Describes characteristics of the trusted Identity Providers.
 * This works in concert with the server setup for simpleSAMLphp.
 *
 * @TODO: This could be set per-site via options in a network setup.
 *
 * @param mixed $value
 * @param string $option_name
 */
function cares_saml_get_idp_associations() {
	return array(
		'heart.org' => 'heart.org',
		'testshib.org' => 'testshib.org',
		// Associative array is important because several domains could point to same idp, like
		// 'missouri.edu' => 'missouri.edu',
		// 'umsystem.edu' => 'missouri.edu',
	);
}

/**
 * Check an email address for membership in a remote IdP.
 * This works in concert with the server setup for simpleSAMLphp.
 *
 * @param string $email_address
 *
 * @return null|string The Identity Provider key if matched. Null otherwise.
 */
function cares_saml_get_idp_by_email_address( $email_address ) {
	$idp = null;
	$domain = substr( strrchr( $email_address, '@' ), 1 );
	$associations = cares_saml_get_idp_associations();

	if ( isset( $associations[ $domain ] ) || array_key_exists( $domain, $associations ) ) {
		$idp = $associations[ $domain ];
	}

	return $idp;
}

/**
 * Provides default options for WP SAML Auth.
 *
 * @param mixed $value
 * @param string $option_name
 */
function cares_wpsa_filter_option( $value, $option_name ) {
	$defaults = array(
		/**
		 * Path to SimpleSAMLphp autoloader.
		 *
		 * Follow the standard implementation by installing SimpleSAMLphp
		 * alongside the plugin, and provide the path to its autoloader.
		 * Alternatively, this plugin will work if it can find the
		 * `SimpleSAML_Auth_Simple` class.
		 *
		 * @param string
		 */
		// 'simplesamlphp_autoload' => dirname( __FILE__ ) . '/simplesamlphp/lib/_autoload.php',
		'simplesamlphp_autoload' => '/var/simplesamlphp/lib/_autoload.php',

		/**
		 * Authentication source to pass to SimpleSAMLphp
		 *
		 * This must be one of your configured identity providers in
		 * SimpleSAMLphp. If the identity provider isn't configured
		 * properly, the plugin will not work properly.
		 *
		 * @param string
		 */
		'auth_source'            => 'default-sp',
		/**
		 * Whether or not to automatically provision new WordPress users.
		 *
		 * When WordPress is presented with a SAML user without a
		 * corresponding WordPress account, it can either create a new user
		 * or display an error that the user needs to contact the site
		 * administrator.
		 *
		 * @param bool
		 */
		'auto_provision'         => true,
		/**
		 * Whether or not to permit logging in with username and password.
		 *
		 * If this feature is disabled, all authentication requests will be
		 * channeled through SimpleSAMLphp.
		 *
		 * @param bool
		 */
		'permit_wp_login'        => true,
		/**
		 * Attribute by which to get a WordPress user for a SAML user.
		 *
		 * @param string Supported options are 'email' and 'login'.
		 */
		'get_user_by'            => 'email',
		/**
		 * SAML attribute which includes the user_login value for a user.
		 *
		 * @param string
		 */
		'user_login_attribute'   => 'uid',
		/**
		 * SAML attribute which includes the user_email value for a user.
		 *
		 * @param string
		 */
		'user_email_attribute'   => 'mail',
		/**
		 * SAML attribute which includes the display_name value for a user.
		 *
		 * @param string
		 */
		'display_name_attribute' => 'display_name',
		/**
		 * SAML attribute which includes the first_name value for a user.
		 *
		 * @param string
		 */
		'first_name_attribute' => 'first_name',
		/**
		 * SAML attribute which includes the last_name value for a user.
		 *
		 * @param string
		 */
		'last_name_attribute' => 'last_name',
		/**
		 * Default WordPress role to grant when provisioning new users.
		 *
		 * @param string
		 */
		'default_role'           => get_option( 'default_role' ),
	);
	$value = isset( $defaults[ $option_name ] ) ? $defaults[ $option_name ] : $value;
	return $value;
}
add_filter( 'cares_wp_saml_auth_option', 'cares_wpsa_filter_option', 0, 2 );