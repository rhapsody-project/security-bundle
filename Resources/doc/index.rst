MongoDB Acl Provider
====================

Installation using composer
---------------------------

To install MongoDBAclBundle using composer add following line to you composer.json file::

    # composer.json
    "iampersistent/mongodb-acl-bundle": "dev-master"

Use the composer update command to start the installation. After the installation add following line into the bundles array in your AppKernel.php file::

    # AppKernel.php
    new IamPersistent\MongoDBAclBundle\IamPersistentMongoDBAclBundle()

Configuration
-------------

To use the MongoDB Acl Provider, the minimal configuration is adding acl_provider to the MongoDb config in config.yml::

    # app/config/config.yml
    iam_persistent_mongo_db_acl:
        acl_provider: 
            default_database: %mongodb_database_name%

The next requirement is to add the provider to the security configuration::

    # app/config/security.yml
    services:
        mongodb_acl_provider:
            parent: doctrine_mongodb.odm.security.acl.provider

    security:
        acl:
            provider: mongodb_acl_provider



The full acl provider configuration options are listed below::

    # app/config/config.yml
    iam_persistent_mongo_db_acl:
        acl_provider:
            default_database: ~
            collections:
                entry: ~
                object_identity: ~


To initialize the MongoDB ACL run the following command::

    php bin/console init:acl:mongodb
    
    
Refresh Tokens
--------------

You may also want to support JWT refresh tokens, allowing a user to seamlessly
reauthenticate even after their initial JWT authentication token expires. This
behaves similarly to the "Remember Me" token in conventional authentication.

To enable refresh tokens::

    # app/config/security.yml
    firewalls:
        ...
        
        refresh:
            pattern: ^/auth/token-refresh
            stateless: true
            anonymouse: true
            json_login:
                check_path: /auth/token-refresh

    access_control:
        ...
        - { path: ^/auth/token-refresh, roles: IS_AUTHENTICATED_ANONYMOUSLY }
        ...

TBW

Test keys are protected with the passphrase: "to boldly go..."