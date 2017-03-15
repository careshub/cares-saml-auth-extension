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
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_scripts' ) );

		// Before logging in, check if the user is required to log in against a remote identity provider.
		add_filter( 'authenticate', array( $this, 'maybe_force_remote_idp_login' ),  21, 3 );

		// Log the user out of the remote auth provider when they log out of WordPress.
		// add_action( 'wp_logout', array( $this, 'simplesamlphp_logout' ) );

		// Change the behavior of wp-login.php
		// Add a hidden input so we know when requests come from the "Single Sign on" form.
		add_action( 'login_form', array( $this, 'login_form_add_action_input' ) );
		// Add an SSO link to the bottom of the login forms.
		add_action( 'cares_after_login_form', array( $this, 'login_forms_add_sso_link' ) );

		// Intercept password reset requests for users that authenticate against external identity providers
		add_action( 'lostpassword_post', array( $this, 'check_lost_password_request' ) );

		// Registration improvements
		add_filter( 'cc_registration_extras_email_validate_message', array( $this, 'registration_check_sso_domain' ) );
		// Make a random password for remote IdP-authenticated users
		add_filter( 'bp_signup_pre_validate', array( $this, 'randomize_password_for_sso_users' ), 20 );
		// For new users that authenticate against an SSO, require authentication before the account is created.
		add_action( 'bp_signup_validate', array( $this, 'maybe_require_validation_against_idp' ), 8 );

		// Support for remote login enabled by "CC JSON Login" plugin.
		// If a user must log in with a remote identity provider, return an error and a login url.
		add_action( 'cc_json_login_before_login', array( $this, 'maybe_stop_cc_json_login' ) );
		// Maybe log the user in during a cookie check.
		add_action( 'cc_json_login_before_cookie_check', array( $this, 'filter_cc_json_login_status_check' ) );
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
		// Scripts
		wp_enqueue_script( $this->plugin_slug . '-plugin-script', plugins_url( 'js/public.js', __FILE__ ), array( 'jquery' ), $this->version, true );
	}


	/**
	 * Register and enqueue public-facing style sheet.
	 *
	 * @since    1.0.0
	 */
	public function enqueue_login_scripts() {
		// Scripts
		wp_enqueue_script( $this->plugin_slug . '-login-plugin-scripts', plugins_url( 'js/login.js', __FILE__ ), array( 'jquery' ), $this->version, true );

		wp_localize_script( $this->plugin_slug . '-login-plugin-scripts', 'SSO_login', array(
				'sso_login_url' => esc_url( add_query_arg( 'action', 'use-sso', wp_login_url() ) ),
			)
		);
	}

	// Working with simpleSAMLphp **********************************************

	/**
	 * Use simpleSAMLphp to attempt a remote login.
	 *
	 * @since 1.0.0
	 *
	 * @param null|WP_User|WP_Error $user     WP_User if the user is authenticated.
	 *                                        WP_Error or null otherwise.
	 * @param string                $username Username or email address.
	 */
	private function do_saml_authentication( $idp = null ) {

		$idp_provider = $this->get_simplesamlphp_auth_instance( $idp );

		// Don't continue if simpleSAMLphp isn't set up.
		if ( ! $idp_provider ) {
			return null;
		}

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
			return $existing_user;
		}

		/*
		 * If the user doesn't already exist, try to create a new user.
		 */
		if ( ! self::get_option( 'auto_provision' ) ) {
			// Add some useful attributes for new accounts.
			$query_args = array(
				'sso_email' => $attributes[ $attribute ][0],
				'sso_username' => $attributes[ 'uid' ][0],
			);

			$display_name = '';
			if ( ! empty( $attributes['display_name'][0] ) ) {
				$display_name = $attributes['display_name'][0];
			} elseif ( ! empty( $attributes['first_name'][0] ) && ! empty( $attributes['last_name'][0] ) ) {
				$display_name = $attributes['first_name'][0] . ' ' . $attributes['last_name'][0];
			}
			if ( $display_name ) {
				$query_args['sso_displayname'] = $display_name;
			}

			$registration_url = esc_url( add_query_arg(
				$query_args,
				wp_registration_url() ) );

			return new WP_Error( 'wp_saml_auth_auto_provision_disabled', sprintf( __( 'No Community Commons account exists with your email address. Please <a href="%s">register</a> for a new account.', 'wp-saml-auth' ), $registration_url ) );
		}

		$user_args = array();
		foreach ( array( 'display_name', 'user_login', 'user_email', 'first_name', 'last_name' ) as $type ) {
			$attribute = self::get_option( "{$type}_attribute" );
			$user_args[ $type ] = ! empty( $attributes[ $attribute ][0] ) ? $attributes[ $attribute ][0] : '';
		}
		$user_args['role'] = self::get_option( 'default_role' );
		$user_args['user_pass'] = wp_generate_password();

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
	 * Create a new SimpleSAML_Auth_Simple object.
	 *
	 * @since 1.0.0
	 *
	 * @param string $auth_source Which remote identity provider to use.
	 *
	 * @return SimpleSAML_Auth_Simple object
	 */
	private function get_simplesamlphp_auth_instance( $auth_source = null ) {
		$auth_source = $this->choose_auth_source( $auth_source );

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
			return false;
		}

		return new SimpleSAML_Auth_Simple( $auth_source );
	}

	/**
	 * Get the user's simpleSAMLphp session info if it exists.
	 *
	 * @since 1.0.0
	 *
	 * @return string The id of the remote identity provider.
	 */
	private function get_simplesamlphp_session() {
		$session = false;

		$simplesamlphp_path = self::get_option( 'simplesamlphp_autoload' );
		if ( file_exists( $simplesamlphp_path ) ) {
			require_once( $simplesamlphp_path );
		}

		if ( ! class_exists( 'SimpleSAML_Session' ) ) {
			add_action( 'admin_notices', function() {
				if ( current_user_can( 'manage_options' ) ) {
					echo '<div class="message error"><p>' . wp_kses_post( sprintf( __( "WP SAML Auth wasn't able to find the <code>SimpleSAML_Session</code> class. Please check the <code>simplesamlphp_autoload</code> configuration option, or <a href='%s'>visit the plugin page</a> for more information.", 'wp-saml-auth' ), 'https://wordpress.org/plugins/wp-saml-auth/' ) ) . '</p></div>';
				}
			});
			return;
		}

		// Get the session details.
		return SimpleSAML_Session::getSessionFromRequest();
	}

	/**
	 * Get the user's auth source as set in the simpleSAMLphp session.
	 *
	 * @since 1.0.0
	 *
	 * @return string The id of the remote identity provider.
	 */
	private function get_auth_source_from_session() {
		$auth = null;
		$session = $this->get_simplesamlphp_session();
		if ( $session ) {
			$auth  = $session->getAuthorities();
			if ( is_array( $auth ) ) {
				$auth = current( $auth );
			}
		}
		return $auth;
	}

	/**
	 * Filter or choose an auth source with fallbacks and validation.
	 *
	 * @since 1.0.0
	 *
	 * @param string The id of the remote identity provider.
	 *
	 * @return string The id of the remote identity provider.
	 */
	private function choose_auth_source( $auth = null ) {
		if ( ! $auth ) {
			$auth = $this->get_auth_source_from_session();
		}
		if ( ! $auth ) {
			$auth = self::get_option( 'auth_source' );
		}

		// Validate the auth source
		$idps = cares_saml_get_available_idps();
		if ( ! in_array( $auth, $idps ) ) {
			$auth = 'default-sp';
		}

		return $auth;
	}

	// Changing WP behaviors ***************************************************

	/**
	 * Before logging in, check if the user is required to log in against a
	 * remote identity provider.
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
		$email_address = cares_saml_get_email_from_login_form_input( $username, 'current' );

		/*
		 * If we've got an email address and it belongs to one of our remote
		 * authorization sources, refer the authorization to that identity provider.
		 */
		if ( $email_address && $idp = cares_saml_get_idp_by_email_address( $email_address ) ) {
			$user = $this->do_saml_authentication( $idp );
		}

		/*
		 * If this came from the "Sign in with SSO" page, and the login
		 * didn't go through, determine the error state.
		 */
		if ( ! ( $user instanceof WP_User )
			 && isset( $_REQUEST['login-form-action-parameter'] )
			 && 'use-sso' == $_REQUEST['login-form-action-parameter'] ) {
			if ( ! $email_address ) {
				return new WP_Error( 'cares_saml_auth_lookup_email_required', __( 'Please provide a valid email address.', 'wp-saml-auth' ) );
			} elseif ( null == cares_saml_get_idp_by_email_address( $email_address ) ) {
				return new WP_Error( 'cares_saml_auth_lookup_email_required', __( 'No remote identity provider for this site is associated with your email address.', 'wp-saml-auth' ) );
			}
		}

		return $user;
	}

	/**
	 * Log the user out of the remote auth provider when they log out of WordPress.
	 *
	 * @since 1.0.0
	 *
	 * @param string $auth_source Which remote identity provider to use.
	 */
	public function simplesamlphp_logout( $auth_source = null ) {
		$auth_source = $this->choose_auth_source( $auth_source );

		if ( $auth_source ) {
			$idp_provider = $this->get_simplesamlphp_auth_instance( $auth_source );
			$idp_provider->logout( add_query_arg( 'loggedout', true, wp_login_url() ) );
		}
	}

	/**
	 * Add a login form input that passes the action variable from the login form used.
	 *
	 * @since 1.0.0
	 */
	public function login_form_add_action_input() {
		$action = '';
		if ( ! empty( $_GET['action'] ) ) {
			$action = $_GET['action'];
		}
		?><input type="hidden" name="login-form-action-parameter" id="login-form-action-parameter" value="<?php echo $action; ?>">
		<?php
	}

	/**
	 * Add a hidden login form input that passes the action variable from the login form used.
	 *
	 * @since 1.0.0
	 */
	public function login_forms_add_sso_link() {
		printf( __( '<a href="%s" class="log-in-with-sso">Log In Using SSO</a>', 'cares-saml-auth' ), esc_url( add_query_arg( 'action', 'use-sso', wp_login_url() ) ) );
	}

	/**
	 * Intercept 'lost password' requests for users whose password are
	 * managed by a remote identity provider.
	 *
	 * @since 1.0.0
	 *
	 * @param WP_Error object.
	 */
	public function check_lost_password_request( $errors ) {
		$email_address = null;

		// Does this user have a Community Commons account?
		$username = isset( $_POST['user_login'] ) ? $_POST['user_login'] : '';
		$email_address = cares_saml_get_email_from_login_form_input( $username, 'current' );

		// If this user exists, do they use an external identity provider?
		if ( $email_address && $idp = cares_saml_get_idp_by_email_address( $email_address ) ) {
			// If yes, pass them to the identity provider, since we can't help reset their password.
			$errors->add( 'must_authenticate_with_sso', sprintf( __('<strong>ERROR</strong>: Your password is maintained by a remote identity provider. Visit your <a href="%s">organization\'s login pane</a> to continue.' ), cares_saml_get_login_url_for_idp( $idp, esc_url( add_query_arg( 'action', 'use-sso', wp_login_url() ) ) ) ) );
		}
	}

	/**
	 * Check if the registered email address is authenticated by a remote identity provider.
	 *
	 * @since 1.0.0
	 *
	 * @param array $response Response details to be returned.
	 */
	public function registration_check_sso_domain( $response ) {
		$response['sso_auth_required'] = 0;
		$response['sso_domain'] = '';

		// Only work if the email address is OK so far.
		if ( ! empty( $response['valid_address'] ) && $idp = cares_saml_get_idp_by_email_address( $_POST['email'] ) ) {
			$response['sso_auth_required'] = 1;
			$response['sso_domain'] = $idp;
		}

		return $response;
	}

	/**
	 * If the new user uses a remote identity provider, give them a long and random password,
	 * since they'll never need it.
	 *
	 * @since 1.0.0
	 */
	public function randomize_password_for_sso_users() {
		// We interact with $_POST variables only here.
		if ( isset( $_POST['signup_email'] ) && cares_saml_get_idp_by_email_address( $_POST['signup_email'] ) ) {
			// This user must login via SSO, so make a hard-to-guess password, since the user will never need it.
			$password = wp_generate_password( rand( 12, 20 ) );
			$_POST['signup_password'] = $password;
			$_POST['signup_password_confirm'] = $password;
		}
	}

	/**
	 * For new users that will authenticate against an remote identity provider,
	 * require authentication before the account is created.
	 *
	 * @since 1.0.0
	 *
	 * @param $user_data WP_User object
	 */
	public function maybe_require_validation_against_idp() {
		$bp = buddypress();

		if ( isset( $bp->signup->email ) && $idp = cares_saml_get_idp_by_email_address( $bp->signup->email ) ) {

			$idp_provider = $this->get_simplesamlphp_auth_instance( $idp );

			// Don't continue if simpleSAMLphp isn't set up.
			if ( ! class_exists( 'SimpleSAML_Auth_Simple' ) || ( ! $idp_provider instanceof SimpleSAML_Auth_Simple ) ) {
				return false;
			}

			$auth = $idp_provider->requireAuth();
			$attributes = $idp_provider->getAttributes();

			// Check that the returned email address matches the address the user submitted.
			if ( $attributes['mail'][0] == $bp->signup->email ) {
				// OK, we're satisfied that this user will sync in the future. Allow registration to continue.
				return;
			} else {
				$bp->signup->errors['signup_email'] = __( 'You must use the same email address here that you use to log in at your remote identity provider', 'cares-saml-auth' );

				// Add some useful attributes for new accounts using short-duration cookies.
				setcookie( 'sso_email', $attributes['mail'][0], time()+60, COOKIEPATH, COOKIE_DOMAIN, is_ssl() );
				setcookie( 'sso_username', $attributes[ 'uid' ][0], time()+60, COOKIEPATH, COOKIE_DOMAIN, is_ssl() );

				$display_name = '';
				if ( ! empty( $attributes['display_name'][0] ) ) {
					$display_name = $attributes['display_name'][0];
				} elseif ( ! empty( $attributes['first_name'][0] ) && ! empty( $attributes['last_name'][0] ) ) {
					$display_name = $attributes['first_name'][0] . ' ' . $attributes['last_name'][0];
				}
				setcookie( 'sso_displayname', $display_name, time()+60, COOKIEPATH, COOKIE_DOMAIN, is_ssl() );
			}

			// Don't check the captcha again... it'll fail
			if ( function_exists( 'Ncr_BP_Registration_Captcha::validate_captcha_registration_field' ) ) {
				remove_action( 'bp_signup_validate', 'Ncr_BP_Registration_Captcha::validate_captcha_registration_field' );
			}
		}
	}

	// Support for remote login via "CC JSON Login" plugin. ********************

	/**
	 * If a user must log in with a remote identity provider, return an error and a login url.
	 *
	 * @since 1.0.0
	 *
	 * @param string $username The login name (or email address) provided by the user.
	 */
	public function maybe_stop_cc_json_login( $username ) {
		if ( $email_address = cares_saml_get_email_from_login_form_input( $username, 'strict' ) ) {
			if ( $idp = cares_saml_get_idp_by_email_address( $email_address ) ) {

				$idp_provider = $this->get_simplesamlphp_auth_instance( $idp );
				// If this user isn't authenticated, stop processing and send an error message back.
				// Otherwise, we'll let the wp_signon() happen.
				if ( ! $idp_provider instanceof SimpleSAML_Auth_Simple || ! $idp_provider->isAuthenticated() ) {
					$response = array(
						'userid' 	 => 0,
						'message' 	 => 'This user must log in using a remote identity provider.',
						'sso_login'  => cares_saml_get_login_url_for_idp( $idp ),
					);

					// Send response.
					header("content-type: text/javascript; charset=utf-8");
					header("Access-Control-Allow-Origin: *");
					echo htmlspecialchars($_GET['callback']) . '(' . json_encode( $response ) . ')';

					exit;
				}

			}
		}
	}

	/**
	 * If a user has an active session set up with a remote identity provider,
	 * we may be able to perform a signon when an AJAX login check is performed.
	 *
	 * @since 1.0.0
	 *
	 * @return JSON response|void
	 */
	public function filter_cc_json_login_status_check() {

		if ( ! is_user_logged_in() && $idp = $this->get_auth_source_from_session() ) {
			$idp_provider = $this->get_simplesamlphp_auth_instance( $idp );

			if ( $idp_provider instanceof SimpleSAML_Auth_Simple && $idp_provider->isAuthenticated() ) {

				$attributes = $idp_provider->getAttributes();
				$get_user_by = self::get_option( 'get_user_by' );
				$attribute = self::get_option( "user_{$get_user_by}_attribute" );
				if ( empty( $attributes[ $attribute ][0] ) ) {
					return new WP_Error( 'wp_saml_auth_missing_attribute', sprintf( esc_html__( '"%s" attribute missing in SimpleSAMLphp response. Please contact your administrator.', 'wp-saml-auth' ), $get_user_by ) );
				}

				$user = wp_signon( array( 'user_login' => $attributes[ $attribute ][0], 'user_password' => 'placeholder' ) );

				if ( ( $user instanceof WP_User ) && $user->ID ) {
					// Get the user's hubs
					$groups = groups_get_user_groups( $user->ID );
					$group_ids = $groups['groups'];
					$response = array(
						'userid' 	=> $user->ID,
						'login' 	=> $user->user_login,
						'email' 	=> $user->user_email,
						'groups'	=> $group_ids
					);

					// Send response and stop processing.
					header("content-type: text/javascript; charset=utf-8");
					header("Access-Control-Allow-Origin: *");
					echo htmlspecialchars($_GET['callback']) . '(' . json_encode( $response ) . ')';

					exit;
				}
			}
		}
	}

}
