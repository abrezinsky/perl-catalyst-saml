package Catalyst::Authentication::Credential::SAML2;

# ABSTRACT: SAML authentication provider for Catalyst

use Moose;
use namespace::autoclean;

use Net::SAML2;
use MIME::Base64 qw/ decode_base64 /;
use Crypt::OpenSSL::Random;
use Catalyst::Exception;

=head1 SYNOPSIS

In MyApp.pm

 use Catalyst qw/
   Authentication
   Session
   Session::Store::FastMmap
   Session::State::Cookie
 /;

 MyApp->config(
   "Plugin::Authentication" => {
     default_realm => "saml2",
       realms => {
         saml2 => {
           store => {
             class => "DBIx::Class", # This should be your usual store
             user_class => "MyApp::Users",
           },
           credential => {
             class => "SAML2",
             saml_org_contact => "Config Test Contact",
             saml_org_name => "Config Test Organization",
             saml_org_display_name => "Config Display Name",
             sso_field => "fsso_id",
             ca_cert_file => "your_certificate_authority_certs.pem",
             cert_file => "your_sp_certificate.pem",
             default_idp_metadata => "https://idp.your.domain/path/to/metadata.xml",
           },
         },
       },
    },
 );

Then create a SAML Controller:

  package MyApp::Controller::Auth::SAML2;

  use Moose;

  BEGIN { extends 'CatalystX::Controller::Authentication::SAML2'; }

  __PACKAGE__->config( realm => "saml2" ); # Should match your realm name above
  __PACKAGE__->meta->make_immutable;
  1;

Then whenever you want to authenticate someone using SAML:

  $c->authenticate(undef, 'saml2');


=head1 DESCRIPTION

This module implements SAML2 Service Provider functionality for Catalyst's Authentication framework. 

It does not need to be the only authentication method and needs a normal store.  Usually this will be the same as your backup or primary authentication source (eg. Password).

Because of some of the complexities involved with using the base Net::SAML2 module, you should always inherit from the shipped CatalystX::Controller::Authentication::SAML2 class.  This class implements all of the functionality required for SAML, such as the response endpoints and the metadata endpoints.  Feel free to wrap the base methods in begin/around/after Moose magic if you need to change the behavior.

In your application, a call to $c->authenticate(undef, 'saml2') without POST data will cause a redirect to your class that extends CatalystX::Controller::Authentication::SAML2.  This redirect will trigger a redirection to the configured IdP with a valid SAMLRequest.  Once the IdP has verified the identity of the user, they will post back to your application which will handle the response and authenticate the user.

=cut

around BUILDARGS => sub {
	my $orig = shift;
	my $class = shift;
	my ($config, $c, $realm) = @_;

	if ( $realm ) {
		my $provider_config = $realm->{config}->{credential};
		return $class->$orig({ realm => $realm, %$provider_config });
	}
	else {
		return $class->$orig( @_ );
	}
};

=head1 ATTRIBUTES

=head2 realm (required)

This should be the same realm name as what you have defined as your authentication realm in your configuration.

=cut

has 'realm'  => (is => 'ro', required => 1);

=head2 sso_field (required)

This attribute is used as the field to lookup the user based on the incoming NameID assertion.  If the NameID of the identity provider is the same as your username field, you can just use that on your DBIx::Class result.

=cut

has 'sso_field'  => (is => 'ro', required => 1);

=head2 ca_cert_file (required)

Your SP requires the CA Root certificate for your own cert_file (see below) as well as  the Root certificate for your Identity Provider.  This should point to the path (relative to CATALYST_HOME) where the file is located.

=head cert_file (required)

Your SP requires its own certificate file identifying itself for encryption purposes.  This should point to the path (relative to CATALYST_HOME) where the file is located.

=cut

has 'ca_cert_file'  => (is => 'ro', required => 1);
has 'cert_file'     => (is => 'ro', required => 1);

=head2 default_idp_metadata (required)

This is the metadata URL for your IdP.  In the future, you will be able to support multiple Identity Providers.  If using ADFS, the structure follows: https://your.adfs.server/FederationMetadata/2007-06/FederationMetadata.xml

=cut

has 'default_idp_metadata'     => ( is => 'rw', isa => 'Str', required => 1 );

=head2 saml_org_name 

This field sets the Organization Name record on the Metadata endpoint.

=head2 saml_org_display_name

This field sets the Organization Display Name record on the Metadata endpoint.

=head2 saml_org_contact

This fields sets the Organziation Contact record on the Metadata endpoint.

=cut

has 'saml_org_name'         => ( is => 'rw', isa => 'Str', default => sub { 'SAML Application' } );
has 'saml_org_display_name' => ( is => 'rw', isa => 'Str', default => sub { 'SAML Application' } );
has 'saml_org_contact'      => ( is => 'rw', isa => 'Str', default => sub { 'SAML Application' } );

=head2 override_entity_id 

If your metadata url provides a different entity id than what your IdP wants, you can override this here.  If you're using ADFS, the value is probably https://your.adfs.server/adfs/ls

=head2 override_saml_url

The SAML url is automatically set on the Service Provider object, if it's wrong, you can override it here.

=head2 override_saml_id

The SAML id is automatically set on the Service Provider object, if it's wrong, you can override it here.
 
=cut

has 'override_entity_id'     => ( is => 'rw', isa => 'Str' );
has 'override_saml_url'      => ( is => 'rw', isa => 'Str' );
has 'override_saml_id'       => ( is => 'rw', isa => 'Str' );

has '_base_class_obj' => ( is => 'rw', isa => "CatalystX::Controller::Authentication::SAML2" );
has '_base_class_args' => ( is => 'rw', isa => "HashRef" );


=head1 METHODS
=cut

sub _get_url {
	my ($self, $c) = @_;

	return $self->override_saml_url if $self->override_saml_url;

	my $id = $self->_get_id($c);
	$id =~ s/\/saml$//;
	return $id;
}

sub _get_id {
	my ($self, $c) = @_;

	return $self->override_saml_id if $self->override_saml_id;

	my $bc = $self->_base_class_obj;
	return $c->uri_for( "/" . $bc->action_namespace )->as_string;
}

sub _sp {
	my ($self, $c) = @_;

	my $sp = Net::SAML2::SP->new(
		id     => $self->_get_id($c),
		url    => $self->_get_url($c),
		cert   => $self->cert_file,
		cacert => $self->ca_cert_file,

		# SAML description items
		org_name         => $self->saml_org_name,
		org_display_name => $self->saml_org_display_name,
		org_contact      => $self->saml_org_contact,
	);

	return $sp;
}

sub _idp {
	my ($self,$c) = @_;

	my $idp = Net::SAML2::IdP->new_from_url(
		url    => $self->default_idp_metadata,
		cacert => $self->ca_cert_file,
	);

	return $idp;
}

=head2 idp_redirect_url

Generate the URL used to redirect the user to the IdP.  This includes the SAMLRequest URL parameter.

=cut

sub idp_redirect_url {
	my ($self, $c) = @_;

	my $sp = $self->_sp($c);
	my $idp = $self->_idp($c);

	my $entity = $idp->entityid;
	$entity = $self->override_entity_id if $self->override_entity_id;

	my $authnreq = $sp->authn_request(
		$entity,
		$idp->format, # default format.
	);

	# This is a hack, a really bad hack.
	# ADFS doesn't allow ID's that start with numbers, only A-Z_.-, etc.  Since the attribute is ro, we have
	# to peak into the object and hand edit the id.
	$authnreq->{id} = "_" . unpack 'H*', Crypt::OpenSSL::Random::random_pseudo_bytes(16);

	my $redirect = $sp->sso_redirect_binding($idp, 'SAMLRequest');

	return $redirect->sign($authnreq->as_xml);
}

=head2 authenticate

When called during the normal course of your application, will redirect the user to the IdP and kick off the authentication with the SAML provider.  It will return -1 during this action.

When called by CatalystX::Controller:Authentication::SAML2, it will parse the SAMLResponse from the IdP and try to authenticate the user, returning the User Object, if successful or undef if not.

=cut

sub authenticate {
	my ($self, $c, $realm, $authinfo) = @_;

	Catalyst::Exception->throw("Unable to find your subclassed version of CatalystX::Controller::Authentication::SAML2")
		unless $self->_base_class_obj;

	# If we're being called without a SAMLResponse, then redirect the user...
	# We return -1 so you know to just detach()
	unless ( $c->req->method eq "POST" and $c->req->params->{SAMLResponse} ) {
		$c->response->redirect( $self->idp_redirect_url($c) );
		return -1;
	}

	# Otherwise, we have something and we should try to verify our response was legitimate
	my $ret = Net::SAML2::Binding::POST->new(
		cacert => $self->ca_cert_file,
	)->handle_response(
		$c->req->params->{SAMLResponse}
	);

	Catalyst::Exception->throw("Invalid assertion returned from IDP")
		unless $ret;

	my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
		xml => decode_base64($c->req->params->{SAMLResponse})
	);

	my $user_obj = $realm->find_user({
		$self->sso_field => $assertion->nameid,
	}, $c);

	return $user_obj;
}

=head2

Return a string of the correctly formatted Metadata for this Service Provider

=cut

sub metadata {
	my ($self, $c) = @_;
	return $self->_sp($c)->metadata;
}

1;
