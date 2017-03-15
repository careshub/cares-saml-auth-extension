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

	// Helper function to parse URL parameters
	function getUrlParameter( name ) {
		name = name.replace(/[\[]/, '\\[').replace(/[\]]/, '\\]');
		var regex = new RegExp('[\\?&]' + name + '=([^&#]*)');
		var results = regex.exec(location.search);
		return results === null ? '' : decodeURIComponent(results[1].replace(/\+/g, ' '));
	};

}(jQuery));