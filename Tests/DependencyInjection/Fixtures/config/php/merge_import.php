<?php

$container->loadFromExtension('rhapsody_security', array(
    'jwt' => array(
        'enabled' => true,
        'public_key_path' => '/path/to/jwt/public.key',
        'private_key_path' => '/path/to/jwt/private.key',
        'pass_phrase' => 'notsecret',
        'token_ttl' => 3600,
        'payload' => array(
            'adapter' => 'rhapsody_security.jwt.adapter.payload_adapter.default',
            'identity_claim' => 'identity',
            'claims' => array(
                'identity' => array('name' => 'username', 'property' => 'username', 'required' => true),
                'roles' => array('name' => 'roles', 'required' => true),
            )
        ),
        'encoder' => array(
            'service' => 'rhapsody_security.jwt.encode.default',
            'signature_algorithm' => 'RS256',
            'crypto_engine' => 'openssl',
        )
    ),
));
