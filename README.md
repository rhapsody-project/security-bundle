Rhapsody SecurityBundle
=======================

[![Build Status](https://secure.travis-ci.org/rhapsody-project/RhapsodySecurityBundle.png?branch=master)](http://travis-ci.org/rhapsody-project/RhapsodySecurityBundle)

This bundle provides extensions to the core Symfony Security component.

## JWT Support

The JWT support in this bundle is based off of the amazing [Lexik JWT 
Authentication Bundle](https://github.com/lexik/LexikJWTAuthenticationBundle)
and we are especially grateful to:

* [Robin Chalas](https://github.com/chalasr)
* [Nicolas Cabot](https://github.com/slashfan)
* ... and all of the other contributors to the aforementioned project.

Despite the excellence of the Lexik JWT authentication bundle certain features,
such as refreshing a JWT token, were not built into the bundle natively. In
addition to this (and for other reasons) we made the decision to roll the JWT
authentication code into the Rhapsody SecurityBundle to provide a more complete
security solution.

While the code has its roots in the Lexik JWT authentication bundle it has
already, and will continue, to grow independently to support the needs of the
Rhapsody Projects and to follow our best practices. 