(function ( $ ) {
	"use strict";

	// Registration form changes
	if ( $( ".buddypress.register" ) ){
		// At page load, pre-fill the username and email address if possible.
		var sso_email = getUrlParameter( 'sso_email' ) || '',
			sso_username = getUrlParameter( 'sso_username' ) || '',
			sso_displayname = getUrlParameter( 'sso_displayname' ) || '';

		if ( sso_email.length ) {
			$( "#signup_email, #signup_email_confirm").val( sso_email ).trigger( "change" );
		}
		if ( sso_username.length ) {
			$( "#signup_username").val( sso_username ).trigger( "change" );
		}
		if ( sso_displayname.length ) {
			$( 'input[name="field_1"]' ).val( sso_displayname );
		}

		// Create a password management message container.
		$( "#signup_password" ).parents( ".editfield" ).append( '<p class="validated password_management" style="display:none"></p>' );

		// If the AJAX email checker returns true, hide the password input.
		$( "#signup_form" ).on( "ajax_response_email_verified", function( resp ){
			if ( resp.response.sso_auth_required ) {
				if ( resp.response.sso_domain ) {
					var message = "Your password will be maintained by your identity provider, " + resp.response.sso_domain + ".";
				} else {
					var message = "Your password will be maintained by your identity provider.";
				}
				// Fill and hide the password inputs.
				$( "#signup_password, #signup_password_confirm" ).val( "auto-generated" ).hide();
				$( "#signup_password_confirm" ).parents( ".editfield" ).hide();
				// Show the password management message.
				$( "#signup_password").siblings( ".password_management" ).html( message ).show();
			} else {
				// Fill and hide the password inputs.
				$( "#signup_password, #signup_password_confirm" ).val( "" ).show();
				$( "#signup_password_confirm" ).parents( ".editfield" ).show();
				// Show the password management message.
				$( "#signup_password").siblings( ".password_management" ).html( "" ).hide();
			}
		});
	}

	// Helper function to parse URL parameters
	function getUrlParameter( name ) {
		name = name.replace(/[\[]/, '\\[').replace(/[\]]/, '\\]');
		var regex = new RegExp('[\\?&]' + name + '=([^&#]*)');
		var results = regex.exec(location.search);
		return results === null ? '' : decodeURIComponent(results[1].replace(/\+/g, ' '));
	};

}(jQuery));
