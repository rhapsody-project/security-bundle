<?php

$container->loadFromExtension('security', array(
    // ** Providers
    'providers' => array(
        'default' => array(
            'id' => 'foo'
        ),
    ),

    // ** Firewalls
    'firewalls' => array(
        'default' => array(
            'jwt_login' => true,
            'jwt_refresh' => true
        ),
        'custom_path' => array(
            'jwt_login' => true,
            'jwt_refresh' => array('path' => '/my/path')
        ),
        'full' => array(
            'jwt_login' => true,
            'jwt_refresh' => array()
        ),
    ),
));
