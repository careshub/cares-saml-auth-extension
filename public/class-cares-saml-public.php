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
		add_action( 'bp_init', array( $this, 'maybe_enqueue_bp_styles_scripts' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_scripts' ) );

		// Before logging in, check if the user is required to log in against a remote identity provider.
		add_filter( 'authenticate', array( $this, 'maybe_force_remote_idp_login' ),  21, 3 );

		// If the user has followed a "login to a specific remote IDP" url, forward them to their IDP.
		// This action is called when ?action=sso_forward query arg is present on login form.
		add_action( 'login_form_sso_forward', array( $this, 'forward_login_to_remote_idp' ) );

		// Log the user out of the remote auth provider when they log out of WordPress.
		// Generally disabled. Enable it by setting `'logout_upstream' => true`
		// in your `cares_wp_saml_auth_option` filter function.
		add_action( 'wp_logout', array( $this, 'simplesamlphp_logout' ) );

		add_filter( 'login_redirect', array( $this, 'maybe_redirect_after_saml_auth' ), 999, 3 );

		// Change the behavior of login forms
		// Store any redirect_to strings as cookies for later use.
		add_action( 'login_init', array( $this, 'store_redirect_to_as_cookie' ) );

		// Maybe force remote authentication
		add_action( 'login_init', array( $this, 'maybe_pass_login_request_directly_to_idp' ), 12 );

		// Add a hidden input on wp-login.php so we know when requests come from the "Single Sign on" form.
		add_action( 'login_form', array( $this, 'login_form_add_action_input' ) );
		// Add an SSO link to the bottom of login forms in the CC theme.
		add_action( 'cares_after_login_form', array( $this, 'login_forms_add_sso_link' ) );
		// Add an SSO link to the bottom of login forms created by the "cares login forms" plugin.
		add_action( 'cares_login_widget_form', array( $this, 'login_forms_add_sso_link' ) );

		// Intercept password reset requests for users that authenticate against external identity providers
		add_action( 'lostpassword_post', array( $this, 'check_lost_password_request' ) );

		// Registration improvements - WordPress registration process.
		// Replace the "new account, set password" email with "welcome, please log in" email.
		add_filter( 'wp_mail', array( $this, 'filter_new_account_email' ) );

		// Registration improvements - BuddyPress specific.
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

		// Support for a "log into WP redirect" stop.
		add_action( 'wp_ajax_nopriv_cares-saml-auth-wp-login', array( $this, 'catch_ajax_post_auth_redirect' ) );
		add_action( 'wp_ajax_cares-saml-auth-wp-login', array( $this, 'catch_ajax_post_auth_redirect' ) );
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
	 * Register and enqueue BuddyPress-specific assets.
	 *
	 * @since    1.0.0
	 */
	public function maybe_enqueue_bp_styles_scripts() {
		// Scripts for Registration
		if ( bp_is_register_page() ) {
			add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_bp_reg_scripts' ) );
		}

	}

	/**
	 * Register and enqueue public-facing style sheet.
	 *
	 * @since    1.0.0
	 */
	public function enqueue_bp_reg_scripts() {
		// Scripts
		wp_enqueue_script( $this->plugin_slug . 'bp-registration-plugin-script', plugins_url( 'js/bp-registration-mods.js', __FILE__ ), array( 'jquery' ), $this->version, true );
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
				'sso_login_url' => cares_saml_create_sso_login_url(),
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

		if ( cares_saml_enable_logging() ) {
			cares_saml_write_log( 'Attributes returned from IdP: ' . print_r( $attributes, true ) );
		}

		$get_user_by = self::get_option( 'get_user_by' );
		$existing_user = false;

		// If 'idp_user_id' is specified, the comparison is against a meta value.
		if ( 'idp_user_id' === $get_user_by && isset( $attributes['idp_user_id'][0] ) ) {
			$meta_matches = get_users( array(
				'meta_key'     => $idp . '_idp_user_id',
				'meta_value'   => $attributes['idp_user_id'][0],
			) );

			if ( $meta_matches ) {
				$existing_user = current( $meta_matches );
			} else {
				// This is temporary, and will be removed once the accounts are synced.
				$get_user_by = 'email';
			}
		}

		/*
		 * Attempt to log the user into WP using the email address or username
		 * (whichever is specified in cares_wp_saml_auth_option)
		 * provided by the remote Identity Provider.
		 */
		if ( ! $existing_user && 'idp_user_id' !== $get_user_by ) {
			$attribute = self::get_option( "user_{$get_user_by}_attribute" );
			if ( empty( $attributes[ $attribute ][0] ) ) {
				return new WP_Error( 'wp_saml_auth_missing_attribute', sprintf( esc_html__( '"%s" attribute missing in SimpleSAMLphp response. Please contact your administrator.', 'wp-saml-auth' ), $get_user_by ) );
			}
			$existing_user = get_user_by( $get_user_by, $attributes[ $attribute ][0] );
		}

		if ( $existing_user ) {
			/**
			 * Fires after a user is logged in via SAML authentication.
			 *
			 * @since 1.3.0
			 *
			 * @param WP_User $existing_user The WP_User object for the logged-in user.
			 * @param string  $idp           The ID of the remote identity provider.
			 * @param array   $attributes    The user attributes returned by the remote identity provider.
			 */
			do_action( 'after_saml_auth_logged_in', $existing_user, $idp, $attributes );

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

			return new WP_Error( 'wp_saml_auth_auto_provision_disabled', sprintf( __( 'No account exists with your email address. Please <a href="%s">register</a> for a new account.', 'wp-saml-auth' ), $registration_url ) );
		}

		$user_args = array();
		foreach ( array( 'display_name', 'user_login', 'user_email', 'first_name', 'last_name' ) as $type ) {
			$attribute = self::get_option( "{$type}_attribute" );
			$user_args[ $type ] = ! empty( $attributes[ $attribute ][0] ) ? $attributes[ $attribute ][0] : '';
		}
		$user_args['role'] = self::get_option( 'default_role' );
		$user_args['user_pass'] = wp_generate_password();

		$user_args = apply_filters( 'wp_saml_auth_insert_user', $user_args );

		// If using the 'idp_user_id' assocation method, only insert the user if we can make the association.
		if ( 'idp_user_id' === $get_user_by ) {
			if ( isset( $attributes['idp_user_id'][0] ) ) {
				$user_id = wp_insert_user( $user_args );
			} else {
				return new WP_Error( 'wp_saml_auth_idp_provided_no_id',  __( 'Your identity provider is not returning the necessary data to create an account.', 'wp-saml-auth' ) );
			}
		} else {
			// More common case.
			$user_id = wp_insert_user( $user_args );
		}

		// Was the user creation successful?
		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		} else {

			// If using the 'idp_user_id' assocation method, create the usermeta.
			// if ( 'idp_user_id' === $get_user_by ) {
			// Using the existence of this attribute, because the get_user_by method may fallback to email if not found.
			if ( isset( $attributes['idp_user_id'][0] ) ) {
				update_user_meta( $user_id, $idp . '_idp_user_id', $attributes['idp_user_id'][0] );
			}

			/**
			 * Fires after a new user is provisioned via SAML authentication.
			 *
			 * @since 1.0.0
			 *
			 * @param int    $user_id    The ID of the newly created user.
			 * @param string $idp        The ID of the remote identity provider.
			 * @param array  $attributes The user attributes returned by the remote identity provider.
			 */
			do_action( 'after_saml_auth_provisioned_user', $user_id, $idp, $attributes );
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
		$idp = null;
		/*
		 * If the email address's domain is served by a remote Identity Provider,
		 * we must not allow the user to log in with his local WP credentials.
		 * Instead, send the user to simpleSAMLphp for remote auth.
		 */
		if ( $user instanceof WP_User ) {
			// If the WP_User object's already been set, we know the email address.
			$email_address = $user->user_email;
		} else if ( isset( $_GET['sso-forward-to'] ) ) {
			$idp = $_GET['sso-forward-to'];
		} elseif ( empty( $username ) ) {
			// If we don't have a $user object or username to work with, bail out.
			return $user;
		}

		// If we don't know the email address, try to find it.
		// If auto account provision is not allowed, limit check to existing users.
		$auto_provision = ( self::get_option( 'auto_provision' ) ) ? 'any' : 'current';
		$email_address = cares_saml_get_email_from_login_form_input( $username, $auto_provision );

		// If an IDP has been specified, forward the user on.
		if ( ! is_null( $idp ) ) {
			$user = $this->do_saml_authentication( $idp );
		/*
		 * If we've got an email address and it belongs to one of our remote
		 * authorization sources, refer the authorization to that identity provider.
		 */
		} else if ( $email_address && $idp = cares_saml_get_idp_by_email_address( $email_address ) ) {
			$user = $this->do_saml_authentication( $idp );
		/*
		 * If we're requiring remote authentication, refer the authorization to an identity provider.
		 */
		} else if ( cares_saml_must_use_remote_auth() ) {
			// Do we know which IDP to use?
			$idps = cares_saml_get_idps_for_site();
			if ( 1 === count( $idps ) ) {
				$user = $this->do_saml_authentication( current( $idps ) );
			} else {
				// We can't guess, we'll need more info, but in the meantime we need to prevent the login.
				return new WP_Error( 'cares_saml_auth_lookup_email_required', __( 'Please provide a valid email address.', 'wp-saml-auth' ) );
			}
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
	 * If the user has followed a "login to a specific remote IDP" url,
	 * forward them to their IDP.
	 * This is hooked to a custom action in wp-login.php.
	 *
	 * @since 1.0.1
	 */
	public function forward_login_to_remote_idp() {
		if ( ! is_user_logged_in() && $_GET['action'] === 'sso_forward' ) {
			wp_signon( array(
				'user_login' => 'remote-sso-user',
				'user_password' => 'notrealpw'
			) );
		}
	}

	/**
	 * If the site requires loggin in using an IDP,
	 * forward the user to their IDP.
	 *
	 * @since 1.1.0
	 */
	public function maybe_pass_login_request_directly_to_idp() {
		if ( ! is_user_logged_in() && cares_saml_must_use_remote_auth() ) {
			// Resolve logouts to the home page.
			if ( isset( $_GET['loggedout'] ) ) {
				wp_redirect( site_url() );
				exit();
			// Avoid redirect loops.
			} else if ( ! isset( $_GET['action'] ) || ! in_array( $_GET['action'], array( 'sso_forward', 'use-sso' ), true ) ) {
				wp_redirect( cares_saml_create_sso_login_url() );
				exit();
			}
		}
	}

	/**
	 * Upon login form init, store any redirect_to query args
	 * as cookies so we can access those values after login.
	 *
	 * @since 1.1.0
	 */
	public function store_redirect_to_as_cookie() {
		// Before passing the user off to the IDP, store the redirect_to as a cookie for use after login.
		if ( ! empty( $_GET['redirect_to'] ) ) {
			setcookie( 'redirect_to', $_GET['redirect_to'] );
		}
	}

	/**
	 * If a redirect_to cookie is set use it to calculate redirect after login.
	 *
	 * @since 1.1.0
	 */
	public function maybe_redirect_after_saml_auth( $redirect_to, $requested_redirect_to, $user  ) {
		if ( isset( $_COOKIE['redirect_to'] ) ) {
			$redirect_to = $_COOKIE['redirect_to'];
		}

		return $redirect_to;
	}

	/**
	 * Log the user out of the remote auth provider when they log out of WordPress.
	 *
	 * @since 1.0.0
	 *
	 * @param string $auth_source Which remote identity provider to use.
	 */
	public function simplesamlphp_logout( $auth_source = null ) {
		if ( ! self::get_option( 'logout_upstream' ) ) {
			return;
		}

		$auth_source = $this->choose_auth_source( $auth_source );

		if ( $auth_source ) {
			$idp_provider = $this->get_simplesamlphp_auth_instance( $auth_source );
			$idp_provider->logout( add_query_arg( 'loggedout', true, get_home_url() ) );
			SimpleSAML_Session::getSessionFromRequest()->cleanup();
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
		$possible_domains = cares_saml_get_sso_domains_for_site();

		$sso_login_url = cares_saml_create_sso_login_url();
		if ( stripos( $sso_login_url, 'sso_forward' ) ) {
			$class = 'log-in-with-sso-forward';
		} else {
			$class = 'log-in-with-sso';
		}

		if ( $class ) {
			printf( __( '<a href="%s" class="%s">Log In Using SSO</a>', 'cares-saml-auth' ),
				esc_url( $sso_login_url ),
				$class
			);

			// Add the necessary script.
			$this->enqueue_login_scripts();
		}
	}

	/**
	 * If the new vanilla-WP-created account must use SSO, change the
	 * "set password" email.
	 *
	 * Vanilla WP registration works like this:
	 *    - User signs up with username and email, but does not choose a password.
	 *    - WP creates a random password, then generates a "set password" email
	 *      that relies on the standard WP "reset password" process.
	 *    - Once you reset your password, you're invited to log in.
	 *
	 * @param array $args A compacted array of wp_mail() arguments, including the "to" email,
	 *                    subject, message, headers, and attachments values.
	 */
	public function filter_new_account_email( $args ) {
		if ( strpos( $args['subject'], 'Your username and password info' ) ) {

			if ( ! empty( $args['to'] ) && $idp = cares_saml_get_idp_by_email_address( $args['to'] ) ) {
				$user = get_user_by( 'email', $args['to'] );
				$locale = function_exists( 'get_user_locale' ) ? get_user_locale( $user ) : get_locale();
				$switched_locale = switch_to_locale( $locale );

				$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
				$args['subject'] = sprintf( __( 'Thank you for joining %s' ), $blogname );

				$message = sprintf( __( 'Username: %s'), $user->user_login ) . "\r\n\r\n";
				$message .= sprintf( __( 'Your password will be maintained by the authentication service at %s.' ), $idp ) . "\r\n\r\n";
				$message .= __( 'To log in, visit the following address:' ) . "\r\n\r\n";
				$message .= wp_login_url() . "\r\n";

				$args['message'] = $message;

				if ( $switched_locale ) {
					restore_previous_locale();
				}
			}
		}
		return $args;
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
			if ( strtolower( $attributes['mail'][0] ) == strtolower( $bp->signup->email ) ) {
				// OK, we're satisfied that this user will sync in the future. Allow registration to continue.
				return;
			} else {
				$bp->signup->errors['signup_email'] = sprintf( __( 'You must use the same email address here that is associated with your account at %s. If you are not %s, please log out of %s to continue.', 'cares-saml-auth' ), $idp, $attributes['mail'][0], $idp );

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
		if ( $email_address = cares_saml_get_email_from_login_form_input( $username, 'current' ) ) {
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

	/**
	 * For remote logins via an AJAX request, the user's request is sent to:
	 * - simpleSAMLphp install at the login host
	 * - remote identity provider
	 * - simpleSAMLphp install at the login host
	 * - /wp-admin/admin-ajax.php at the login host (this step is handled by this function)
	 * - back to where the user started from (maps.cc.org or similar)
	 *
	 * @since 1.0.0
	 *
	 * @return JSON response|void
	 */
	public function catch_ajax_post_auth_redirect() {

		$redirect = isset( $_REQUEST['redirect'] ) ? $_REQUEST['redirect'] : site_url();

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

				if ( $user instanceof WP_User ) {
					/**
					 * Fires after a user is authenticated via SAML authentication.
					 *
					 * @since 1.3.0
					 *
					 * @param int    $user_id    The ID of the newly authenticated user.
					 * @param string $idp        The ID of the remote identity provider.
					 * @param array  $attributes The user attributes returned by the remote identity provider.
					 */
					do_action( 'after_saml_auth_user_signon', $user->ID, $idp, $attributes );
				}

			}
		}

		wp_redirect( $redirect );
		die();
	}

}
