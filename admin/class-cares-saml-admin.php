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
 * administrative side of the WordPress site.
 *
 * If you're interested in introducing public-facing
 * functionality, then refer to `public/class-cc-mocwp.php`
 *
 * @package Cares_Saml_Auth_Admin
 * @author  dcavins
 */

class CARES_SAML_Admin {

	/**
	 * Slug of the plugin screen.
	 *
	 * @since    1.0.0
	 *
	 * @var      string
	 */
	protected $plugin_screen_hook_suffix = null;

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
	 * Initialize the plugin by loading admin scripts & styles and adding a
	 * settings page and menu.
	 *
	 * @since     1.0.0
	 */
	public function __construct() {
		$this->version = cares_saml_get_plugin_version();
	}

	public function add_hooks() {
		/*
		 * Only network admins should be able to configure this plugin
		 */
		if ( ! is_super_admin() ) {
			return;
		}

		// Load admin style sheet and JavaScript.
		// add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_scripts_and_styles' ) );

		// Add the single-site options page and menu item.
		add_action( 'admin_menu', array( $this, 'add_plugin_admin_menu' ) );
		// Add settings to the single-site admin page.
		add_action( 'admin_menu', array( $this, 'settings_init' ) );

		// Add an action link labeled "Settings" pointing to the options page from the plugin listing.
		$plugin_basename = plugin_basename( plugin_dir_path( __DIR__ ) . $this->plugin_slug . '.php' );
		add_filter( 'plugin_action_links_' . $plugin_basename, array( $this, 'add_action_links' ) );
	}

	/**
	 * Register and enqueue admin-specific style sheets and javascript files.
	 *
	 * @since     1.0.0
	 *
	 * @return    null    Return early if no settings page is registered.
	 */
	public function enqueue_admin_scripts_and_styles() {

		if ( ! isset( $this->plugin_screen_hook_suffix ) ) {
			return;
		}

		$screen = get_current_screen();
		if ( $this->plugin_screen_hook_suffix == $screen->id ) {
			wp_enqueue_style( $this->plugin_slug .'-admin-styles', plugins_url( 'assets/css/admin.css', __FILE__ ), array(), $this->version );
			wp_enqueue_script( $this->plugin_slug . '-admin-script', plugins_url( 'assets/js/admin.js', __FILE__ ), array( 'jquery' ), $this->version );
		}
	}

	/**
	 * Register the administration menu for this plugin into the WordPress Dashboard menu.
	 *
	 * @since    1.0.0
	 */
	public function add_plugin_admin_menu() {

		$this->plugin_screen_hook_suffix = add_options_page(
			__( 'Single Sign-On', 'cares-saml-auth' ),
			__( 'Single Sign-On', 'cares-saml-auth' ),
			'manage_options',
			$this->plugin_slug,
			array( $this, 'display_plugin_admin_page' )
		);

	}

	/**
	 * Render the settings page for this plugin.
	 *
	 * @since    1.0.0
	 */
	public function display_plugin_admin_page() {
		// include_once( 'views/admin.php' );
		// Note that update/get/delete_site_option sets site option _or_ network options if multisite.
		// Note that update/get/delete_option sets option for current site.
		?>
		<div class="wrap">
			<?php screen_icon(); ?>
			<h2><?php echo esc_html( get_admin_page_title() ); ?></h2>

			<form action="<?php echo admin_url( 'options.php' ) ?>" method='post'>

				<?php
				settings_fields( $this->plugin_slug );
				do_settings_sections( $this->plugin_slug );
				submit_button();
				?>

			</form>

		</div>
		<?php
	}

	/**
	 * Add settings action link to the plugins page.
	 *
	 * @since    1.0.0
	 */
	public function add_action_links( $links ) {

		return array_merge(
			array(
				'settings' => '<a href="' . admin_url( 'options-general.php?page=' . $this->plugin_slug ) . '">' . __( 'Settings', 'cares-saml-auth' ) . '</a>'
			),
			$links
		);

	}

	/**
	 * Register the settings and set up the sections and fields for the
	 * global settings screen.
	 *
	 * @since    1.0.0
	 */
	public function settings_init() {

		// Setting for showing groups directory as tree.
		add_settings_section(
			'cares_sso_section_1', // Section ID
			__( 'Configure Remote Identity Providers for this Site.', 'cares-saml-auth' ), // Title
			array( $this, 'render_cares_sso_section_1' ), // Callback
			$this->plugin_slug // Page
		);

		register_setting(
			$this->plugin_slug, // Option group
			'sso_required_domains', // Option ID
			array(
				'sanitize_callback' => 'cares_saml_sanitize_sso_required_domains',
			)
		);
		add_settings_field(
			'sso_idp_associations', // Option ID
			__( 'Choose which SSO rules to enable for this site.', 'cares-saml-auth' ), // Title
			array( $this, 'render_email_address_idp_associations' ), // Render callback
			$this->plugin_slug, // Page
			'cares_sso_section_1' // Section ID
		);

	}

	public function render_cares_sso_section_1() {
		// echo "section callback";
	}
	public function render_email_address_idp_associations() {
		$value = get_option( 'sso_idp_associations' );
		$all_idps = cares_saml_get_idp_associations();
		$selected_idps = cares_saml_get_sso_domains_for_site();
		?>
		<p>Note that a trust relationship must be set up with each identity provider that should be used with this site (meaning they'll be expecting logins from this specific site). <a href="<?php echo site_url(); ?>/simplesaml/module.php/core/frontpage_federation.php" target="_blank">Access the SAML metadata for this site.</a></p>
		<p>Checking these check boxes is the last step, and then users who have an email address with a chosen domain <strong>will be required</strong> to log in against that domain's identity provider.</p>
		<hr />
		<fieldset id="sso_idp_associations">
			<legend class="screen-reader-text"><?php _e( 'Choose which SSO rules to enable for this site.', 'cares-saml-auth' ); ?></legend>
			<?php foreach( $all_idps as $email_domain => $idp ) : ?>
				<input type="checkbox" name="sso_required_domains[]" value="<?php echo $email_domain; ?>" id="sso_idp_associations-<?php echo $email_domain; ?>"<?php if ( in_array( $email_domain, $selected_idps ) ) { echo ' checked="checked"'; } ?>> <label for="sso_idp_associations-<?php echo $email_domain; ?>"> Users using the email domain <code><?php echo $email_domain; ?></code> must authenticate with <code><?php echo $idp; ?></code></label><br />
			<?php endforeach; ?>
		</fieldset>

		<?php
	}
}
