package CatalystX::Controller::Authentication::SAML2;

# ABSTRACT: Auth controller for SAML login functionality

use Moose;
use namespace::autoclean;
BEGIN { extends 'Catalyst::Controller::REST'; }

use Net::SAML2;
use MIME::Base64 qw/ decode_base64 /;
use Crypt::OpenSSL::Random;

has 'realm'  => (is => 'ro', required => 1);
has 'credential' => ( is => 'ro', lazy_build => '1', required => '1' );

sub _build_credential {
	my $self = shift;
	return $self->_app->get_auth_realm( $self->realm )->credential;
}

# This lets us register this controller with the plugin so the plugin knows where it is and can get URLs off of it.
# Also gives us a place to do some sanity checking about our environment.
after create_action => sub {
	my ($self, %args) = @_;

	# We want to find our base class, we can use that to find the rest
	return if $args{name} ne 'base';

	Catalyst::Exception
		->throw("Due to a limitation in Net::SAML2, your URL namespace MUST end with saml.  Please rename your controller to MyApp::Controller::*::SAML instead of " . $args{class} . "\n\n")
		unless $args{namespace} =~ /\/saml$/;

	Catalyst::Exception
		->throw("Unable to find the SAML2 realm in " . $args{class} .
			"\nPlease be sure to set __PACKAGE__->config( realm => 'FOO' ) where FOO is the realm name in your credential config\n\n")
		unless $self->realm;

	my $cred = $self->credential;

	Catalyst::Exception
		->throw("Unable to find configured credential for your realm.  Please double check your authentication plugin credential configuration for SAML2.")
		unless $cred;

	# Don't allow more than one class use, it really makes no sense
	if ($cred->_base_class_args) {
		my $found = $cred->_base_class_args->{class};

		Catalyst::Exception
			->throw("CatalystX::Controller::Authentication::SAML2 is already subclassed in your application.  You should only have one of them.  Also found at $found\n");
	}

	$cred->_base_class_obj($self);
	$cred->_base_class_args(\%args);
};


=head1 DESCRIPTION

This is an authentication controller that can be subclassed in your
project. It provides functionality to allow your project to be authenticated
using SAML.

This controller assumes that your project is already configured with the
Authentication and Session Catalyst plugins.

=cut

=head1 ENDPOINTS

=cut

sub base : Chained("/") PathPrefix Local CaptureArgs(0) {}

=head2 metadata

Returns metadata for your SAML2 Service Provider.  Includes your internal certificate and the URLs available for service bindings.

=cut

sub metadata : Chained('base') Args(0) ActionClass('REST') {
}

=head3 GET <base>/saml/metadata

Return metadata for this SAML2 SP

=cut

sub metadata_GET {
	my ( $self, $c ) = @_;

        $c->response->content_type('text/xml');
        $c->response->body( $self->credential->metadata($c) );

	return;
}

=head2 login

Redirect our user to the IdP for authentication.  You can redirect the user here and it will forward them to the default IdP configured.

In the future, it will take a ?idp=<url> argument to configure which IdP to redirect them to.

=cut

sub login : Chained('base') Args(0) ActionClass('REST') {}

=head3 GET <base>/saml/login

Redirects the user to the configured IdP

=cut

sub login_GET {
	my ( $self, $c ) = @_;

	# Since we don't have any POST data, this will cause a redirect.
	# Capture return code and see if it's -1 to do something else.
	$c->authenticate(undef, $self->realm );

        return;
}

=head3 POST <base>/saml/consumer-post

Handle the redirect from the IdP and parse the response

=cut

sub consumer_post : Chained('base') PathPart('consumer-post') {
	my ($self, $c) = @_;

	Catalyst::Exception->throw("Must include SAMLResponse parameter") 
		unless $c->req->param('SAMLResponse');

	my $assertion;

	if ( $c->authenticate(undef, $self->realm) ) {
		$c->forward('result_login', [$assertion]);
	}
	else {
		$c->forward('result_no_user_found', [$assertion]);
	}

	return;
}


=head1 PRIVATE ACTIONS

=head2 result_login

After a user has been successfully authenticated and found in the Authentication store, this function will determine what to do next.  You probably want to redirect the user somewhwere.

=cut

sub result_login : Private {
	my ($self, $c, $assertion) = @_;

	$c->response->redirect("/");
}

=head2 result_no_user_found

After a user has been authenticated, if no user is found locally, this method determines what to do with them.  Usually you'll present a access denied message, or if you want just in time provisioning, you'll do something here to create the user you just tried to find.

=cut

sub result_no_user_found : Private {
	my ($self, $c, $assertion) = @_;

	$c->response->status(403);
	$c->response->body("Access Denied");
}

__PACKAGE__->meta->make_immutable;

1;

