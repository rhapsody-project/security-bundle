<?php
/* Copyright (c) Rhapsody Project
 *
 * Licensed under the MIT License (http://opensource.org/licenses/MIT)
 *
 * Permission is hereby granted, free of charge, to any
 * person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the
 * Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice
 * shall be included in all copies or substantial portions of
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
 * KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
 * OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
namespace Rhapsody\SecurityBundle\Tests\DependencyInjection;

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\DependencyInjection\Configuration;
use Symfony\Component\Config\Definition\Processor;

class ConfigurationTest extends TestCase
{
    /**
     * The minimal, required, configuration to not have any required validation
     * issues.
     *
     * @var array
     */
    protected static $minimalConfig = array(
        'db_driver' => 'custom'
    );

    public function testMinimalViableConfiguration()
    {
        $config = array_merge(self::$minimalConfig, array());

        $processor = new Processor();
        $configuration = new Configuration();
        $result = $processor->processConfiguration($configuration, array($config));

        $this->assertEquals('custom', $result['db_driver']);
    }

    public function testMinimalJwtConfiguration()
    {
        $config = array_merge(self::$minimalConfig, array(
            'jwt' => true
        ));

        $processor = new Processor();
        $configuration = new Configuration();
        $result = $processor->processConfiguration($configuration, array($config));

        $this->assertEquals(array(
            'enabled' => true,
            'private_key_path' => null,
            'public_key_path' => null,
            'pass_phrase' => null,
            'token_ttl' => 3600,
            'payload' => array(
                'adapter' => 'rhapsody_security.jwt.adapter.payload_adapter.default',
                'identity_claim' => 'identity',
                'claims' => array()
            ),
            'encoder' => array(
                'service' => 'rhapsody_security.jwt.encoder.default',
                'signature_algorithm' => 'RS256',
                'crypto_engine' => 'openssl'
            ),
            'token_extractors' => array(
                'authorization_header' => array(
                    'prefix' => 'Bearer',
                    'name' => 'Authorization',
                    'enabled' => true
                ),
                'cookie' => array(
                    'name' => 'BEARER',
                    'enabled' => false
                ),
                'json_body' => array(
                    'name' => 'token',
                    'enabled' => false
                ),
                'query_parameter' => array(
                    'name' => 'bearer',
                    'enabled' => false
                )
            )
        ), $result['jwt']);
    }

    /**
     * @expectedException \Symfony\Component\Config\Definition\Exception\InvalidConfigurationException
     */
    public function testNullPayloadAdapterConfigurationRaisesInvalidConfigurationException()
    {
        $config = array_merge(self::$minimalConfig, array(
            'jwt' => array(
                'enabled' => true,
                'payload' => array(
                    'adapter' => null
                 )
            )
        ));

        $processor = new Processor();
        $configuration = new Configuration();
        $processor->processConfiguration($configuration, array($config));
    }

    /**
     * @expectedException \Symfony\Component\Config\Definition\Exception\InvalidConfigurationException
     */
    public function testEmptyClaimsConfigurationRaisesInvalidConfigurationException()
    {
        $config = array_merge(self::$minimalConfig, array(
            'jwt' => array(
                'enabled' => true,
                'payload' => array(
                    'adapter' => 'rhapsody_security.jwt.adapter.default',
                    'claims' => array()
                )
            )
        ));

        $processor = new Processor();
        $configuration = new Configuration();
        $processor->processConfiguration($configuration, array($config));
    }

    /**
     * @expectedException \Symfony\Component\Config\Definition\Exception\InvalidConfigurationException
     */
    public function testInvalidClaimsConfigurationRaisesInvalidConfigurationException()
    {
        $config = array_merge(self::$minimalConfig, array(
            'jwt' => array(
                'enabled' => true,
                'payload' => array(
                    'adapter' => 'rhapsody_security.jwt.adapter.default',
                    'claims' => array(
                        'identity' => 'foo'
                    )
                )
            )
        ));

        $processor = new Processor();
        $configuration = new Configuration();
        $processor->processConfiguration($configuration, array($config));
    }

    public function testCompleteConfiguration()
    {
        $config = array_merge(self::$minimalConfig, array(
            'jwt' => array(
                'enabled' => true,
                'payload' => array(
                    'adapter' => 'rhapsody_security.jwt.adapter.default',
                    'claims' => array(
                        'identity' => array('name' => 'username', 'property' => 'username', 'required' => true)
                    )
                )
            )
        ));

        $processor = new Processor();
        $configuration = new Configuration();
        $result = $processor->processConfiguration($configuration, array($config));

        $this->assertEquals(array(
            'enabled' => true,
            'private_key_path' => null,
            'public_key_path' => null,
            'pass_phrase' => null,
            'token_ttl' => 3600,
            'payload' => array(
                'adapter' => 'rhapsody_security.jwt.adapter.default',
                'identity_claim' => 'identity',
                'claims' => array(
                    'identity' => array(
                        'name' => 'username',
                        'property' => 'username',
                        'required' => true
                    )
                )
            ),
            'encoder' => array(
                'service' => 'rhapsody_security.jwt.encoder.default',
                'signature_algorithm' => 'RS256',
                'crypto_engine' => 'openssl'
            ),
            'token_extractors' => array(
                'authorization_header' => array(
                    'prefix' => 'Bearer',
                    'name' => 'Authorization',
                    'enabled' => true
                ),
                'cookie' => array(
                    'name' => 'BEARER',
                    'enabled' => false
                ),
                'json_body' => array(
                    'name' => 'token',
                    'enabled' => false
                ),
                'query_parameter' => array(
                    'name' => 'bearer',
                    'enabled' => false
                )
            )
        ), $result['jwt']);
    }
}