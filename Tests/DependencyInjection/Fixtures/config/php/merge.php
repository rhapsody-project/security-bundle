<?php

$this->load('merge_import.php', $container);

$container->loadFromExtension('rhapsody_security', array(
    'db_driver' => 'custom',
    'jwt' => array(
        'enabled' => true,
        'public_key_path' => '/alt/location/of/jwt/public.key',
        'private_key_path' => '/alt/location/of/jwt/private.key',
        'pass_phrase' => 'secret',
        'token_ttl' => 86400,
        'payload' => array(
            'claims' => array(
                'identity' => array('name' => 'foo', 'property' => 'bar', 'required' => true),
                'email' => array('name' => 'email'),
                'subject' => array('name' => 'sub', 'property' => 'id'),
            )
        ),
        'encoder' => array(
            'service' => 'rhapsody_security.jwt.encode.lcobucci',
            'signature_algorithm' => 'RS256',
            'crypto_engine' => 'phpseclib',
        )
    ),
));
