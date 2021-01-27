(function ( $ ) {
	"use strict";

	var sso_email = getUrlParameter( 'sso_email' ),
		action = getUrlParameter( 'action' );

	if ( 'use-sso' === action ) {
		$( "#wp-submit" ).val( "Log In Using SSO" );
		$("label[for='user_login']").html( function ( i, old ) {
		     return old.replace( "Username or ", "" );
		});
		$( "#loginform" ).prepend( '<h3 style="margin-bottom:1em;">Single Sign-On</h3>' );
		$( "#user_pass" ).attr( "disabled", true ).parents( "p" ).hide();
		$( ".forgetmenot" ).hide();
		if ( sso_email ) {
			$( "#user_login" ).val( sso_email );
		}
	} else {
		/* Add the "Sign in With SSO" link. */
		var sso_link = ' | <a href="' + SSO_login.sso_login_url + '">Log In Using SSO</a>';
		$( "p#nav" ).append( sso_link );
	}

	// Add a "Log In Using SSO" toggle to the login forms.
	$( ".log-in-with-sso" ).on( "click", function(e){
		e.preventDefault();
		var switching_to_sso = ! $( ".login-form-password-label" ).hasClass( "using-sso" );

		if ( switching_to_sso ) {
			// Class change handles transition and marks state.
			$( ".login-form-password-label" ).addClass( "using-sso" );
			// Change some labels.
			$( ".log-in-with-sso" ).text( "Cancel SSO Login" );
			$( 'form[name="login-form"]' ).find( "input[type=submit]" ).val( "Log In Using SSO" );
			// Disable/enable the password input.
			$( "input[name=pwd]" ).attr( "disabled", true ).delay( 500 ).parents( "label" ).hide();
		} else {
			// Class change handles transition and marks state.
			$( ".login-form-password-label" ).removeClass( "using-sso" );
			// Change some labels.
			$( ".log-in-with-sso" ).text( "Log In Using SSO" );
			$( 'form[name="login-form"]' ).find( "input[type=submit]" ).val( "Log In" );
			// Disable/enable the password input.
			$( "input[name=pwd]" ).attr( "disabled", false ).delay( 500 ).parents( "label" ).show();
			// $( 'form[name="login-form"]' ).attr('action', 'hostingURL');
		}
	});

	// Helper function to parse URL parameters
	function getUrlParameter( name ) {
		name = name.replace(/[\[]/, '\\[').replace(/[\]]/, '\\]');
		var regex = new RegExp('[\\?&]' + name + '=([^&#]*)');
		var results = regex.exec(location.search);
		return results === null ? '' : decodeURIComponent(results[1].replace(/\+/g, ' '));
	};

}(jQuery));