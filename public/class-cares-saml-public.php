<?php
/**
 * @package   Cares_Saml_Auth
 * @author    dcavins
 * @license   GPL-2.0+
 * @link      http://www.communitycommons.org
 * @copyright 2017 CARES, University of Missouri
 */

/**
 * Plugin class. This class should ideally be used to work with the
 * public-facing side of the WordPress site.
 *
 * If you're interested in introducing administrative or dashboard
 * functionality, then refer to `admin/class-cares_ol-admin.php`
 *
 *
 * @package Cares_Saml_Auth
 * @author  dcavins
 */
class CARES_SAML_Public {

	/**
	 *
	 * The current version of the plugin.
	 *
	 * Plugin version, used for cache-busting of style and script file references.
	 *
	 * @since    1.0.0
	 *
	 * @var      string
	 */
	protected $version = '1.0.0';

	/**
	 *
	 * Unique identifier for your plugin.
	 *
	 *
	 * The variable name is used as the text domain when internationalizing strings
	 * of text. Its value should match the Text Domain file header in the main
	 * plugin file.
	 *
	 * @since    1.0.0
	 *
	 * @var      string
	 */
	protected $plugin_slug = 'cares-saml-auth';

	/**
	 *
	 * Identity Provider.
	 *
	 *
	 * If we've calculated the identity provider, it'll be stored here.
	 *
	 * @since    1.0.0
	 *
	 * @var      false|string
	 */
	protected $identity_provider = false;

	/**
	 * Initialize the plugin by setting localization and loading public scripts
	 * and styles.
	 *
	 * @since     1.0.0
	 */
	public function __construct() {
		$this->version = cares_saml_get_plugin_version();
	}

	public function add_hooks() {
		// Load plugin text domain
		add_action( 'init', array( $this, 'load_plugin_textdomain' ) );

		// Load public-facing style sheet and JavaScript.
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_styles_scripts' ) );

		// Before logging in, check if the user is required to log in against a remote identity provider.
		add_filter( 'authenticate', array( $this, 'maybe_force_remote_idp_login' ),  21, 3 );

		add_action( 'wp_logout', array( $this, 'simplesamlphp_logout' ) );


	}

	/**
	 * Return the plugin slug.
	 *
	 * @since    1.0.0
	 *
	 * @return   string Plugin slug.
	 */
	public function get_plugin_slug() {
		return $this->plugin_slug;
	}

	/**
	 * Load the plugin text domain for translation.
	 *
	 * @since    1.0.0
	 */
	public function load_plugin_textdomain() {
		$domain = $this->plugin_slug;
		$locale = apply_filters( 'plugin_locale', get_locale(), $domain );

		load_textdomain( $domain, trailingslashit( WP_LANG_DIR ) . $domain . '/' . $domain . '-' . $locale . '.mo' );
	}

	/**
	 * Get a configuration option for this implementation.
	 *
	 * @param string $option_name
	 * @return mixed
	 */
	public static function get_option( $option_name ) {
		return apply_filters( 'cares_wp_saml_auth_option', null, $option_name );
	}

	/**
	 * Register and enqueue public-facing style sheet.
	 *
	 * @since    1.0.0
	 */
	public function enqueue_styles_scripts() {
		// Styles
		// wp_enqueue_style( $this->plugin_slug . '-plugin-styles', plugins_url( 'css/public.css', __FILE__ ), array(), $this->version );
		// wp_enqueue_script( $this->plugin_slug . '-plugin-scripts', plugins_url( 'js/public.min.js', __FILE__ ), array( 'jquery' ), $this->version, true );
		//localize data for script
		// wp_localize_script( $this->plugin_slug . '-plugin-scripts', 'CARES_Spreadsheets_Edit', array(
		// 		'root' => esc_url_raw( rest_url() ),
		// 		'nonce' => wp_create_nonce( 'wp_rest' ),
		// 		'current_user_id' => get_current_user_id(),
		// 		'ajax_url' => admin_url( 'admin-ajax.php' )
		// 	)
		// );

		// IE specific
		// global $wp_styles;
		// wp_enqueue_style( $this->plugin_slug . '-ie-plugin-styles', plugins_url( 'css/public-ie.css', __FILE__ ), array(), $this->version );
		// $wp_styles->add_data( $this->plugin_slug . '-ie-plugin-styles', 'conditional', 'lte IE 9' );

	}

	/**
	 * Before logging in, check that the user isn't required to login against a remote identity provider.
	 *
	 * @since    1.0.0

	 * @param null|WP_User|WP_Error $user     WP_User if the user is authenticated.
	 *                                        WP_Error or null otherwise.
	 * @param string                $username Username or email address.
	 * @param string                $password User password
	 */
	public function maybe_force_remote_idp_login( $user, $username, $password ) {
		/*
		 * If the email address's domain is served by a remote Identity Provider,
		 * we must not allow the user to log in with his local WP credentials.
		 * Instead, send the user to simpleSAMLphp for remote auth.
		 */

		if ( $user instanceof WP_User ) {
			// If the WP_User object's already been set, we know the email address.
			$email_address = $user->user_email;
		} elseif ( empty( $username ) ) {
			// If we don't have a $user object or username to work with, bail out.
			return $user;
		}

		// If we don't know the email address, try to find it.
		if ( ! $email_address ) {
			if ( strpos( $username, '@' ) === false ) {
				// If the passed username is not an email address, we need to find the email address.
				$maybe_user = get_user_by( 'login', $username );
				if ( isset( $maybe_user->user_email ) ) {
					$email_address = $maybe_user->user_email;
				}
			} else {
				// The user passed an email address.
				$email_address = $username;
			}
		}

		/*
		 * If we've got an email address and it belongs to one of our remote
		 * authorization sources, refer the authorization to that identity provider.
		 */
		if ( $email_address && $idp = cares_saml_get_idp_by_email_address( $email_address ) ) {
			$user = $this->do_saml_authentication( $idp );
		}

		return $user;
	}

	/**
	 * Do the SAML authentication dance
	 *
	 * @since 1.0.0
	 *
 	 * @param null|WP_User|WP_Error $user     WP_User if the user is authenticated.
	 *                                        WP_Error or null otherwise.
	 * @param string                $username Username or email address.
	 */
	private function do_saml_authentication( $idp ) {
		if ( empty( $idp ) ) {
			$idp = self::get_option( 'auth_source' );
		}

		$idp_provider = $this->get_simplesaml_instance( $idp );

		$idp_provider->requireAuth();
		$attributes = $idp_provider->getAttributes();

		$get_user_by = self::get_option( 'get_user_by' );
		$attribute = self::get_option( "user_{$get_user_by}_attribute" );
		if ( empty( $attributes[ $attribute ][0] ) ) {
			return new WP_Error( 'wp_saml_auth_missing_attribute', sprintf( esc_html__( '"%s" attribute missing in SimpleSAMLphp response. Please contact your administrator.', 'wp-saml-auth' ), $get_user_by ) );
		}

		/*
		 * Attempt to log the user into WP using the email address provided by
		 * the remote Identity Provider.
		 */
		$existing_user = get_user_by( $get_user_by, $attributes[ $attribute ][0] );
		if ( $existing_user ) {
			// Set the auth source as a cookie to use on logout.
			$this->set_auth_source_cookie( $idp );
			return $existing_user;
		}

		/*
		 * If the user doesn't already exist, try to create a new user.
		 */
		if ( ! self::get_option( 'auto_provision' ) ) {
			return new WP_Error( 'wp_saml_auth_auto_provision_disabled', esc_html__( 'No WordPress user exists for your account. Please contact your administrator.', 'wp-saml-auth' ) );
		}

		$user_args = array();
		foreach ( array( 'display_name', 'user_login', 'user_email', 'first_name', 'last_name' ) as $type ) {
			$attribute = self::get_option( "{$type}_attribute" );
			$user_args[ $type ] = ! empty( $attributes[ $attribute ][0] ) ? $attributes[ $attribute ][0] : '';
		}
		$user_args['role'] = self::get_option( 'default_role' );
		$user_args['user_pass'] = wp_generate_password();

		$towrite = PHP_EOL . 'creating user, user_args: ' . print_r( $user_args, TRUE );
		$fp = fopen('/var/simplesamlphp/tshoot.txt', 'a');
		fwrite($fp, $towrite);
		fclose($fp);

		$user_args = apply_filters( 'wp_saml_auth_insert_user', $user_args );
		$user_id = wp_insert_user( $user_args );

		// Was the user creation successful?
		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		} else {

			// Set the auth source as a cookie to use on logout.
			$this->set_auth_source_cookie( $idp );

			/**
			 * Fires after a new user is provisioned via SAML authentication.
			 *
			 * @since 1.0.0
			 *
			 * @param int    $user_id The ID of the newly created user.
			 * @param string $idp     The ID of the remote identity provider.
			 */
			do_action( 'after_saml_auth_provisioned_user', $user_id, $idp );
		}

		return get_user_by( 'id', $user_id );
	}

	/**
	 * Log the user out of the remote auth provider when they log out of WordPress.
	 *
	 * @since 1.0.0
	 *
	 * @param string $auth_source Which remote identity provider to use.
	 */
	public function simplesamlphp_logout() {
		$auth_source = $this->get_auth_source_from_cookie();

		if ( $auth_source ) {
			$idp_provider = $this->get_simplesaml_instance( $auth_source );
			$idp_provider->logout( add_query_arg( 'loggedout', true, wp_login_url() ) );
		}
	}

	/**
	 * Create a new SimpleSAML_Auth_Simple object.
	 *
	 * @since 1.0.0
	 *
	 * @param string $auth_source Which remote identity provider to use.
	 */
	private function get_simplesaml_instance( $auth_source = 'default-sp' ) {
		$simplesamlphp_path = self::get_option( 'simplesamlphp_autoload' );
		if ( file_exists( $simplesamlphp_path ) ) {
			require_once $simplesamlphp_path;
		}

		if ( ! class_exists( 'SimpleSAML_Auth_Simple' ) ) {
			add_action( 'admin_notices', function() {
				if ( current_user_can( 'manage_options' ) ) {
					echo '<div class="message error"><p>' . wp_kses_post( sprintf( __( "WP SAML Auth wasn't able to find the <code>SimpleSAML_Auth_Simple</code> class. Please check the <code>simplesamlphp_autoload</code> configuration option, or <a href='%s'>visit the plugin page</a> for more information.", 'wp-saml-auth' ), 'https://wordpress.org/plugins/wp-saml-auth/' ) ) . '</p></div>';
				}
			});
			return;
		}

		return new SimpleSAML_Auth_Simple( $auth_source );
	}

	/**
	 * Set the user's authentication source as a cookie value.
	 *
	 * @since 1.0.0
	 *
	 * @param string $auth_source User's auth source.
	 */
	private function set_auth_source_cookie( $auth_source ) {
		setcookie( 'sso_auth_source', $auth_source, time()+60*60*24, COOKIEPATH, COOKIE_DOMAIN, is_ssl() );
	}

	/**
	 * Get the user's auth source from the cookie we set at login.
	 *
	 * @since 1.0.0
	 *
	 * @return string The id of the remote identity provider.
	 */
	private function get_auth_source_from_cookie() {
		$auth_source = null;
		if ( ! empty( $_COOKIE['sso_auth_source'] ) ) {
			$auth_source = $_COOKIE['sso_auth_source'];
		}
		return $auth_source;
	}

}
