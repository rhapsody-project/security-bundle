<?php

$container->loadFromExtension('rhapsody_security', array(
    'db_driver' => 'custom',
    'jwt' => array(
        'enabled' => true,
        'public_key_path' => '/path/to/jwt/public.key',
        'private_key_path' => '/path/to/jwt/private.key',
        'pass_phrase' => 'secret',
        'token_ttl' => 7200,
        'payload' => array(
            'adapter' => 'rhapsody_security.jwt.adapter.payload_adapter.lcobucci',
            'identity_claim' => 'identity',
            'claims' => array(
                'identity' => array('name' => 'username', 'property' => 'username', 'required' => true),
                'roles' => array('name' => 'roles', 'property' => 'roles'),
                'email' => array('name' => 'email'),
                'subject' => array('name' => 'sub', 'property' => 'id'),
            )
        ),
        'encoder' => array(
            'service' => 'rhapsody_security.jwt.encode.lcobucci',
            'signature_algorithm' => 'RS256',
            'crypto_engine' => 'openssl',
        )
    ),
));
