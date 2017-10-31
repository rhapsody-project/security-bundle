<?php

$container->loadFromExtension('rhapsody_security', array(
    'db_driver' => 'custom',
    'jwt' => array(
        'enabled' => true
    ),
));
