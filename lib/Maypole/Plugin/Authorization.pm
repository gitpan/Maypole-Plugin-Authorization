package Maypole::Plugin::Authorization;
use strict;
use warnings;

# This module provides role-based authorization for Maypole

our $VERSION = '0.05';

# 2005-01-27 djh v0.03	Modified get_authorized_* to make them work and
#			accept arguments, and improved docs
# 2005-01-28 djh v0.04	Added arg checking to get_authorized_* and an
# 			example for get_authorized_methods. Thanks to
#			Josef Chladek.
# 2005-02-08 djh v0.05	Improved error checking in authorize.

# We can determine whether a given user_id is authorized to invoke a
# particular method in a model_class using the following SQL query:

my $_check_auth_sql = <<SQL ;
    SELECT p.id FROM permissions AS p, role_assignments AS r
    WHERE r.user_id  = ? 
    AND   p.model_class = ?
    AND  (p.method = ? OR p.method = '*')
    AND   p.auth_role_id = r.auth_role_id
    LIMIT 1
SQL

# Main permission-checking method

sub authorize {
    my ($self, $r) = @_;

    # Extract values for permission check
    return undef unless $r->user;
    my $userid     = $r->user->id;
    my $method     = $r->action;
    my $class      = $r->model_class;
    return undef unless $class;

    # Find a class that can run SQL queries for us and make sure the SQL
    # query has been prepared
    my $cdbi_class = $r->config->auth->{user_class};
    $cdbi_class->set_sql(check_authorization => $_check_auth_sql)
        unless $cdbi_class->can('sql_check_authorization');

    # Check the permissions
    return $cdbi_class->sql_check_authorization
			->select_val($userid, $class, $method);
}


# Auxiliary methods for finding lists of authorized classes and methods

my $_get_auth_classes_sql = <<SQL ;
    SELECT DISTINCT p.model_class
    FROM   permissions AS p, role_assignments AS r
    WHERE  r.user_id = ?
    AND    r.auth_role_id = p.auth_role_id
SQL

sub get_authorized_classes {
    my ($r, $userid) = @_;
    return unless $r->user or $userid;
    $userid ||= $r->user->id;
    my $cdbi_class = $r->config->auth->{user_class};
    $cdbi_class->set_sql(get_authorized_classes => $_get_auth_classes_sql)
        unless $cdbi_class->can('sql_get_authorized_classes');
    my $sth = $cdbi_class->sql_get_authorized_classes;
    $sth->execute($userid);
    return map { $_->[0] } @{$sth->fetchall_arrayref};
}


my $_get_auth_methods_sql = <<SQL ;
    SELECT p.method FROM permissions AS p, role_assignments AS r
    WHERE r.user_id  = ? 
    AND   p.model_class = ?
    AND   p.auth_role_id = r.auth_role_id
SQL

sub get_authorized_methods {
    my ($r, $userid, $class) = @_;
    return unless $r->user or $userid;
    $userid ||= $r->user->id;
    $class  ||= $r->model_class;
    return unless $class;
    my $cdbi_class = $r->config->auth->{user_class};
    $cdbi_class->set_sql(get_authorized_methods => $_get_auth_methods_sql)
        unless $cdbi_class->can('sql_get_authorized_methods');
    my $sth = $cdbi_class->sql_get_authorized_methods;
    $sth->execute($userid, $class);
    return map { $_->[0] } @{$sth->fetchall_arrayref};
}

1;

__END__

=head1 NAME

Maypole::Plugin::Authorization - Provide role-based authorization for Maypole applications

=head1 SYNOPSIS

  package BeerDB;
  use Maypole::Application qw(
	Authentication::UserSessionCookie
	Authorization);
  use Maypole::Constants;

  sub authenticate {
    my ($self, $r) = @_;
    ...
    if $self->authorize($r) {
        return OK;
    } else {
        # take application-specific authorization failure action
	...
    }
    ...
  }

  # make web page show just tables for this user
  sub additional_data {
    my $r = shift;
    $r->config->display_tables(
	[ map { $_->table } $r->get_authorized_classes ]
    );
  }

  # meanwhile in a template somewhere ...
  [% ok_methods = request.get_authorized_methods %]
  Can be used to decide whether to display an edit button, for example


=head1 DESCRIPTION

This module provides simple role-based authorization for L<Maypole>.
It uses the database to store permissions, which fits well with Maypole.

It determines whether I<users> are authorized to invoke specific
I<methods> in I<classes>. Normally these will be I<actions> in model
classes. Permission to invoke methods is not granted directly; it is
assigned to I<roles>, and each user may be assigned one or more roles.


=head2 authorize

The C<authorize> method is called in the driver's authenticate method,
though it is explicitly passed the request object and so can be called
from elsewhere if desired.

    package BeerDB;

    sub authenticate {
        my ($self, $r) = @_;
        ...
        if $self->authorize($r) {
            return OK;
        } else {
            # take application-specific auth failure action
        }
        ...
    }

It returns a true value if authorization is granted and C<undef> if not.

C<authenticate> needs to deal with requests with no model class before
calling this method because the response is application-specific.
If such a request gets this far, we just turn it down.
Similarly, C<authenticate> needs to handle requests with no user without
calling C<authorize>.

=head2 get_authorized_classes

  $r->get_authorized_classes;		# current user
  $r->get_authorized_classes($user_id);	# specific user

C<get_authorized_classes> returns the list of classes for which the
current user has some permissions. This can be used to build the list of
tabs in the navbar, for instance. If called with a user id as argument,
it returns the list of classes for which that user has some permissions.

=head2 get_authorized_methods

  $r->get_authorized_methods;
  # methods current user can execute in current model class

  $r->get_authorized_methods($user_id);
  # methods specific user can execute in current model class

  $r->get_authorized_methods($user_id, $class_name);
  # methods specific user can execute in nominated model class

  $r->get_authorized_methods(undef, $class_name);
  # methods current user can execute in nominated model class

C<get_authorized_methods> finds the list of methods that the current
user is entitled to invoke on the current model class. This can be used
to build a menu of permitted actions, for example. If called with a user
id as an argument it returns the list of methods that the given user can
execute in the current model class. Similarly, if called with a class
name, it returns the list of methods that the current user can execute
in that class, while if called with both as arguments, it returns the
list of methods the given user is allowed to call in the stated class.

Here is an example of a possible way to use this method in templates to
decide whether to display buttons for various actions that a user may or
may not be authorized to use:

  [% MACRO if_auth_button(obj, action, permitted_method) BLOCK ;
         IF permitted_method == '*' OR permitted_method == action ;
             button(obj, action) ;
         END ;
     END ;
  %]

  # ... and in other templates ...

  [% ok_methods = request.get_authorized_methods ;
     FOR meth = ok_methods ;
          if_auth_button(item, "edit", meth) ;
          if_auth_button(item, "delete", meth) ;
     END ;
  %]


=head1 DATABASE STRUCTURE

The module depends on four database tables to store the necessary data.

=over

=item users

The C<users> table records details of each individual who has an account
on the system. It is also used by
L<Maypole::Plugin:Authentication::UserSessionCookie> to do user
authentication and session management. Additional columns can be added
to suit whatever other needs you have.

=item auth_roles

Users are not given permissions directly because that causes an
explosion in the table size and an administrative headache.
Instead roles are given permissions and users acquire those permissions
by being assigned to roles. The C<auth_roles> table just records the
name of the role. You could add things like a description if you wish.
The table is not called C<roles> so that the name is left free for your
application to use.

=item role_assignments

C<role_assignments> is a classic many-many link table. Records contain
the id of a user and of a role which the user has been assigned.

=item permissions

The C<permissions> table authorizes a specific role to execute a
particular method in a particular class. The classes are expected to be
the model subclasses and the methods will be the actions, but the scheme
will also work in other situations. To reduce administrative burden and
table size, it is allowed to use a '*' wildcard instead of a method name;
this grants permission to all methods in the class. It would be possible
to add a similar wildcard for classes but there's probably no action
that you want to allow on B<all> classes!

=back

The table definitions to implement this scheme look like this:

  CREATE TABLE users (
	id		INT NOT NULL AUTO_INCREMENT,
	name		VARCHAR(100) NOT NULL,
	UID		VARCHAR(20) NOT NULL,
	password	VARCHAR(20) NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (UID),
  ) TYPE=InnoDB;

  CREATE TABLE auth_roles (
	id		INT NOT NULL AUTO_INCREMENT,
	name		VARCHAR(40) NOT NULL,
	PRIMARY KEY (id),
  ) TYPE=InnoDB;

  CREATE TABLE role_assignments (
	id		INT NOT NULL AUTO_INCREMENT,
	user_id		INT NOT NULL,
	auth_role_id	INT NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (user_id, auth_role_id),
	INDEX (auth_role_id),
	FOREIGN KEY (user_id) REFERENCES users (id),
	FOREIGN KEY (auth_role_id) REFERENCES auth_roles (id),
  ) TYPE=InnoDB;

  CREATE TABLE permissions (
	id		INT NOT NULL AUTO_INCREMENT,
	auth_role_id	INT NOT NULL,
	model_class	VARCHAR(100) NOT NULL,
	method		VARCHAR(100) NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (auth_role_id, model_class, method),
	INDEX (model_class(20)),
	INDEX (method(20)),
	FOREIGN KEY (auth_role_id) REFERENCES auth_roles (id),
  ) TYPE=InnoDB;


=head1 PROCESSING

We can determine whether a given C<user_id> is authorized to invoke a
particular C<method> in a C<model_class> using the following SQL query:

    SELECT p.id FROM permissions AS p, role_assignments AS r
    WHERE r.user_id  = ? 
    AND   p.model_class = ?
    AND  (p.method = ? OR p.method = '*')
    AND   p.auth_role_id = r.auth_role_id
    LIMIT 1

This query is executed in the C<authorize> method which is
called from the driver's C<authenticate> method. (Maypole's terminology
is a little confused about authentication and authorization but the
code works the same either way!)


=head2 administration

The permissions database can be maintained by any person who is assigned
to the I<admin> role. Most administration is performed using normal
Maypole actions and templates such as list, search, addnew, view, edit
and delete.

User administration is separated out to a I<user-admin> role. I don't
yet know whether this will prove beneficial but these people are the
only ones who can access passwords and personal details.

There needs to be special code to allow users to edit their own
passwords, since that is a data-dependent permission as opposed to the
metadata-dependent nature of the authorizations scheme. Such code is
part of the application's authentication scheme.

There is a I<default> role that should be assigned to every user.
Perhaps it should be hardwired in the SQL so that users don't have to be
actually added to the role?

=head2 Use Cases

=over

=item Create new user

User administration mechanisms belong in the domain of the
authentication system, though this authorization module imposes a few
additional requirements.
This action should be permitted to the user-admin role. Newly created
users should automatically be assigned to the 'default' role.

=item User changes password

Should be permitted to the individual user only and perhaps to the
user-admin role.

=item Grant/change/revoke user privileges

=item Create/delete role

=item Alter actions permitted to role

People assigned to the admin role can edit the role_assignments,
permissions and auth_roles tables in the normal Maypole way.

=item Update list of classes

=item Update list of methods

Presently, administrators need to type in the names of the model
subclasses and the actions. The methods C<get_authorized_classes> and
C<get_authorized_methods> could be used to build a specialized template
to populate the relevant form elements.

=item Determine list of classes

This is the C<get_authorized_classes> method.
Given a user ID, find the list of classes for which s/he has some
permissions. This can be used to build the list of tabs in the navbar.

=item Determine list of methods

This is the C<get_authorized_methods> method.
Given a user ID and class name, find the list of methods that the user
is entitled to invoke. This can be used to build a menu of permitted
actions.

=back

=head1 ALTERNATIVES AND FUTURES

There are several alternative possibilities for authorizable entities
and permission checking in addition to the example implementation
provided:

1/ Authorize all actions (i.e. methods with the Exported attribute).
Permission could be enforced in the model's process method just before
calling the action.
PRO: simple to implement, uniform and easy-to-understand
CON: not as flexible as alternatives

2/ Explicit call to authorize() at the beginning of every method that
needs to be authorized.
PRO: Flexible. Very simple to implement initially. Obvious in code
where auth occurs. Auth can be done at points other than method entry
if needed.
CON: Error-prone and awkward to maintain. Increases code complexity.

3/ Provide some other attribute that can be attached to methods to
require them to be authorized, or perhaps in combination with Exported.
For example, the Exported attribute could automatically invoke
authorization as would a new 'Auth' attribute, while a new 'NoAuth'
attribute would declare that the action could proceed without
authorization.

=head1 AUTHOR

Dave Howorth, djh#cpan.org

=head1 THANKS TO

Everybody on the Maypole list, for support, help and code.

=head1 LICENCE

Copyright (c) 2004-2005 Dave Howorth.
You may distribute this code under the same terms as Perl itself.

=cut

