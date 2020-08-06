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
 * The format of the array is "email_domain" => "sso_identity_provider_to_use".
 *
 * @return array
 */
function cares_saml_get_idp_associations() {
	return array(
		'heart.org'    => 'heart.org',
		'testshib.org' => 'testshib.org',
		// Associative array is important because several domains could point to same idp, like
		'umsystem.edu' => 'umsystem.edu',
		'missouri.edu' => 'umsystem.edu',
		'mst.edu'      => 'umsystem.edu',
		'umkc.edu'     => 'umsystem.edu',
		'umh.edu'      => 'umsystem.edu',
		'mizzou.edu'   => 'umsystem.edu',
		'umsl.edu'     => 'umsystem.edu',
		'*.*'          => 'extension2.missouri.edu',
	);
}

/**
 * Fetch an array of known possible remote identity providers.
 * The strings used are the IDs of the authsources set up in simpleSAMLphp.
 *
 * @since 1.0.0
 *
 * @return array
 */
function cares_saml_get_available_idps() {
	return array_unique( array_values( cares_saml_get_idp_associations() ) );
}

/**
 * Fetch an array of known possible remote identity providers.
 * The strings used are the IDs of the authsources set up in simpleSAMLphp.
 *
 * @since 1.0.0
 *
 * @return string URL that will redirect to auth provider.
 */
function cares_saml_get_login_url_for_idp( $idp = null, $return_to = null ) {
	/*
	 * Double redirect approach adds a stop at the WP site after authentication.
	 * Example flow: maps.cc -> cc.org/simplesaml -> remote auth service
	 * -> cc.org/admin-ajax.php to login -> maps.cc.org
	 * Example url: https://www.communitycommons.org/simplesaml/module.php/core/as_login.php?AuthId=testshib.org&ReturnTo=https%3A%2F%2Fwww.communitycommons.org%2Fwp-admin%2Fadmin-ajax.php%3Faction%3Dcares-saml-auth-wp-login%26redirect%3Dhttps%3A%2F%2Fmaps.communitycommons.org%2Fviewer%2F
	 */
	$ajax_args = array(
		'action' => 'cares-saml-auth-wp-login',
	);

	// We want to send the user back to the current page if it's known.
	if ( $return_to ) {
		$ajax_args['redirect'] = $return_to;
	} elseif ( is_null( $return_to ) && $_SERVER['HTTP_REFERER'] ) {
		$ajax_args['redirect'] = $_SERVER['HTTP_REFERER'];
	}

	$ipd_args = array(
		'AuthId'   => $idp,
		// We'll drop by WP on the way back home, to log in.
		// Url encode so that simpleSAML ignores the admin-ajax parameters.
		'ReturnTo' => urlencode( add_query_arg( $ajax_args, admin_url( 'admin-ajax.php' ) ) )
	 );

	$url = add_query_arg( $ipd_args, site_url( '/simplesaml/module.php/core/as_login.php' ) );

	return $url;
}


/**
 * Fetch an array of email address domains that could refer to configured remote
 * identity providers.
 *
 * @since 1.0.0
 *
 * @return array
 */
function cares_saml_get_available_email_domains() {
	return array_keys( cares_saml_get_idp_associations() );
}

/**
 * Fetch an array of email addresses that are configured to authenticate
 * with remote identity providers on this site.
 *
 * @since 1.0.0
 *
 * @return array
 */
function cares_saml_get_sso_domains_for_site() {
	$domains = get_option( 'sso_required_domains' );
	return cares_saml_sanitize_sso_required_domains( $domains );
}

/**
 * Fetch an array of known possible remote identity providers.
 * The strings used are the IDs of the authsources set up in simpleSAMLphp.
 *
 * @since 1.0.0
 *
 * @param array $domains Array of email domains to sanitize
 *
 * @return array Domains that are configured in cares_saml_get_idp_associations().
 */
function cares_saml_sanitize_sso_required_domains( $domains ) {
	// Make sure domains are allowed domains.
	$all_domains = cares_saml_get_available_email_domains();
	return array_values( array_intersect( $all_domains, (array) $domains ) );
}

/**
 * Check an email address for membership in a remote IdP.
 * This works in concert with the server setup for simpleSAMLphp.
 *
 *
 * @since 1.0.0
 * @param string $email_address
 *
 * @return null|string The Identity Provider key if matched. Null otherwise.
 */
function cares_saml_get_idp_by_email_address( $email_address ) {
	$idp = null;
	$domain = substr( strrchr( $email_address, '@' ), 1 );

	// Has this domain been set to require usage of a remote identity provider for this site?
	$sso_domains = cares_saml_get_sso_domains_for_site();
	if ( in_array( $domain, $sso_domains ) ) {
		// If yes, we must find the correct IdP to use.
		$associations = cares_saml_get_idp_associations();

		if ( isset( $associations[ $domain ] ) || array_key_exists( $domain, $associations ) ) {
			$idp = $associations[ $domain ];
		}
	}

	return $idp;
}

/**
 * Find the user's email address from the mixed input of the login form.
 *
 * @since 1.0.0
 *
 * @param string $username The login name or email address provided by the user.
 * @param string $limit    Passing 'current' checks email addresses against current users.
 *                         Passing 'any' just checks the passed email address.
 *
 * @return string|boolean False if none found, email address otherwise.
 */
function cares_saml_get_email_from_login_form_input( $username = '', $limit = 'current' ) {
	$email_address = false;
	$maybe_user    = false;
	$username      = trim( wp_unslash( $username ) );

	// If we don't know the email address, try to find it.
	if ( strpos( $username, '@' ) === false ) {
		// If the passed username is not an email address, we need to find the email address.
		$maybe_user = get_user_by( 'login', $username );
	} else {
		// The user passed an email address.
		if ( $limit === 'any' ) {
			// "Any" means use it without verifying that it belongs to a current user.
			$email_address = $username;
		} else {
			$maybe_user = get_user_by( 'email', $username );
		}
	}

	if ( $maybe_user instanceof WP_User  ) {
		$email_address = $maybe_user->user_email;
	}

	return $email_address;
}

/**
 * Fetch an array of Identity Providers that are configured for use on this site.
 *
 * @since 1.2.0
 *
 * @return array
 */
function cares_saml_get_idps_for_site() {
	$sso_domains = cares_saml_get_sso_domains_for_site();
	$all_idps    = cares_saml_get_idp_associations();
	$sso_idps    = array();
	foreach ( $all_idps as $email => $idp ) {
		if ( in_array( $email, $sso_domains ) ) {
			$sso_idps[] = $idp;
		}
	}
	return array_unique( $sso_idps );
}


/**
 * Generate the SSO login url.
 * If only one Identity Provider is specified, use the "sso_forward" action version.
 * If more than one IdP is specified, use the "use-sso" action version.
 *
 * @since 1.2.0
 *
 * @return string
 */
function cares_saml_create_sso_login_url() {
	// @TODO: Add any existing current query args
	// $q_args = ! empty( $_GET ) ? $_GET : array();
	$q_args = array();
	// if ( isset( $q_args['redirect_to'] ) ) {
	// 	$q_args['redirect_to'] = esc_url_raw( $_GET['redirect_to'] );
	// }
	$sso_login_url = wp_login_url();
	$possible_idps = cares_saml_get_idps_for_site();
	if ( ! empty( $possible_idps ) ) {
		// If there is only one remote IDP, send the user to it.
		if ( 1 === count( $possible_idps ) ) {
			$sso_args = array(
				'action' => 'sso_forward',
				'sso-forward-to' => current( $possible_idps ),
			);
		// If multiple domains are possible, we can't guess which one to use (yet).
		} else {
			$sso_args = array(
				'action' => 'use-sso',
			);
		}
		$q_args = array_merge( $q_args, $sso_args );
		$sso_login_url = add_query_arg( $q_args, $sso_login_url );
	}
	return $sso_login_url;
}

/**
 * Has the site admin checked the "must use SSO for login" box?
 *
 * @since 1.2.0
 *
 * @return bool
 */
function cares_saml_must_use_remote_auth() {
	// @TODO: Respect permit_wp_login setting?
	$must_sso = get_option( 'sso_required_all_logins' );
	return (bool) $must_sso;
}

/**
 * Provides default options for WP SAML Auth.
 *
 * @param mixed $value
 * @param string $option_name
 *
 * @since 1.0.0
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
		'auto_provision'         => false, // was true
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
		 * @param string Possible ptions are 'email', 'login', or 'idp_user_id'.
		 *
		 * 'email' and 'login' options use WP get_user_by(), 'idp_user_id' looks user up via usermeta.
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
		/**
		 * Should the user be logged out upstream when logging out of WordPress?
		 *
		 * @param bool
		 */
		'logout_upstream'      => false,
	);
	$value = isset( $defaults[ $option_name ] ) ? $defaults[ $option_name ] : $value;
	return $value;
}
add_filter( 'cares_wp_saml_auth_option', 'cares_wpsa_filter_option', 0, 2 );
