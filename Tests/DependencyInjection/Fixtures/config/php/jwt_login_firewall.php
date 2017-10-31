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
             'jwt_login' => true
        ),
        'custom_checkpath' => array(
            'jwt_login' => array('check_path' => '/my/check_path')
        ),
        'custom_credentials' => array(
            'jwt_login' => array(
                'username_path' => 'foo',
                'password_path' => 'bar',
            ),
        ),
        'full' => array(
            'jwt_login' => array(
                'login_path' => '/my/login_path',
                'check_path' => '/my/check_path',
                'username_path' => 'foo',
                'password_path' => 'bar',
                'use_forward' => false,
                'require_previous_session' => false,
                'provider' => 'default',
                'remember_me' => true,
                'success_handler' => 'my.authentication.success_handler',
                'failure_handler' => 'my.authentication.failure_handler',
                'failure_path' => '/my/failure_path',
                'failure_path_parameter' => '_my_failure_path_parameter',
                'failure_forward' => false,
                'always_use_default_target_path' => true,
                'default_target_path' => '/my/default_target_path',
                'target_path_parameter' => '_target_path_parameter',
                'use_referer' => true
            ),
        ),
    ),
));
