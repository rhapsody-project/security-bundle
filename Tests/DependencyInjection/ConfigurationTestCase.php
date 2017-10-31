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
use Rhapsody\SecurityBundle\DependencyInjection\RhapsodySecurityExtension;
use Rhapsody\SecurityBundle\RhapsodySecurityBundle;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

abstract class ConfigurationTestCase extends TestCase
{
    private static $containerCache = array();

    /**
     *
     * @param ContainerBuilder $container
     */
    abstract protected function getLoader(ContainerBuilder $container);

    /**
     *
     */
    abstract protected function getFileExtension();

    /**
     *
     * @param unknown $expected
     * @param ChildDefinition $defition
     */
    public static function assertAddClaimCallCount($expected, Definition $defition)
    {
        self::assertMethodCallCount($expected, $defition, 'addClaim');
    }

    /**
     *
     * @param array $expected
     * @param ChildDefinition $actual
     */
    public static function assertClaimArguments(array $expected, Definition $actual)
    {
        $arguments = $actual->getArguments();
        self::assertEquals($expected, $arguments);
    }

    /**
     *
     * @param unknown $container
     * @param unknown $expected
     */
    public static function assertClaims($container, $expected)
    {
        $claims = array_values(
            array_filter($container->getServiceIds(), function ($key) {
                return 0 === strpos($key, 'rhapsody_security.jwt.claims.claim_');
            })
        );

        self::assertEquals(array(), array_diff($expected, $claims));
        self::assertEquals(array(), array_diff($claims, $expected));
    }

    /**
     *
     * @param unknown $expected
     * @param ChildDefinition $defition
     * @param string $method The method name to filter on.
     */
    public static function assertMethodCallCount($expected, Definition $defition, $method = null)
    {
        $methodCalls = $defition->getMethodCalls();
        if (!empty($method)) {
            $methodCalls = array_values(
                array_filter($defition->getMethodCalls(), function ($value, $key) use ($method) {
                    return $method === $value[0];
                }, ARRAY_FILTER_USE_BOTH)
            );
        }
        self::assertEquals($expected, count($methodCalls));
    }

    /**
     *
     * @param unknown $expected
     * @param ChildDefinition $defition
     */
    public static function assertSetIdentityClaimCalled(Definition $defition)
    {
        self::assertMethodCallCount(1, $defition, 'setIdentityClaim');
    }

    public function testClaims()
    {
        $container = $this->getContainer('all');

        $expectedClaims = array(
            'rhapsody_security.jwt.claims.claim_identity',
            'rhapsody_security.jwt.claims.claim_roles',
            'rhapsody_security.jwt.claims.claim_email',
            'rhapsody_security.jwt.claims.claim_subject',
        );
        $this->assertClaims($container, $expectedClaims);
        $this->assertClaimArguments(array('username', 'username', true), $container->getDefinition('rhapsody_security.jwt.claims.claim_identity'));
        $this->assertClaimArguments(array('roles', 'roles', false), $container->getDefinition('rhapsody_security.jwt.claims.claim_roles'));
        $this->assertClaimArguments(array('email', null, false), $container->getDefinition('rhapsody_security.jwt.claims.claim_email'));
        $this->assertClaimArguments(array('sub', 'id', false), $container->getDefinition('rhapsody_security.jwt.claims.claim_subject'));
    }

    public function testEmptyClaimsFromDefaultConfig()
    {
        $container = $this->getContainer('default');

        $claims = array_values(
            array_filter($container->getServiceIds(), function ($key) {
                return 0 === strpos($key, 'rhapsody_security.jwt.claims.claim_');
            })
        );
        $this->assertEmpty($claims);
    }

    public function testMerge()
    {
        $container = $this->getContainer('merge');

        $expectedClaims = array(
            'rhapsody_security.jwt.claims.claim_identity',
            'rhapsody_security.jwt.claims.claim_roles',
            'rhapsody_security.jwt.claims.claim_email',
            'rhapsody_security.jwt.claims.claim_subject',
        );
        $this->assertClaims($container, $expectedClaims);
        $this->assertClaimArguments(array('foo', 'bar', true), $container->getDefinition('rhapsody_security.jwt.claims.claim_identity'));
        $this->assertClaimArguments(array('roles', null, true), $container->getDefinition('rhapsody_security.jwt.claims.claim_roles'));
        $this->assertClaimArguments(array('email', null, false), $container->getDefinition('rhapsody_security.jwt.claims.claim_email'));
        $this->assertClaimArguments(array('sub', 'id', false), $container->getDefinition('rhapsody_security.jwt.claims.claim_subject'));

        $this->assertEquals('/alt/location/of/jwt/public.key', $container->getParameter('rhapsody_security.jwt.public_key_path'));
        $this->assertEquals('/alt/location/of/jwt/private.key', $container->getParameter('rhapsody_security.jwt.private_key_path'));
        $this->assertEquals('secret', $container->getParameter('rhapsody_security.jwt.pass_phrase'));
        $this->assertEquals('86400', $container->getParameter('rhapsody_security.jwt.token_ttl'));

        $this->assertTrue($container->hasDefinition('rhapsody_security.jwt.adapter.payload_adapter.default'));
        $this->assertEquals('rhapsody_security.jwt.adapter.payload_adapter.default', (string) $container->getAlias('rhapsody_security.jwt_payload_adapter'));

        // TODO: Add more assertions?
    }

    public function testJwtManagerFromAll()
    {
        $container = $this->getContainer('all');

        $definition = $container->getDefinition('rhapsody_security.jwt_manager');

        $this->assertSetIdentityClaimCalled($definition);
        $this->assertAddClaimCallCount(4, $definition);
        $this->assertEquals(array(
            new Reference('rhapsody_security.jwt_encoder'),
            new Reference('rhapsody_security.jwt_payload_adapter'),
            new Reference('event_dispatcher')), $definition->getArguments());
    }

    public function testJwtManagerFromDefault()
    {
        $container = $this->getContainer('default');

        $definition = $container->getDefinition('rhapsody_security.jwt_manager');

        $this->assertSetIdentityClaimCalled($definition);
        $this->assertAddClaimCallCount(0, $definition);
        $this->assertEquals(array(
            new Reference('rhapsody_security.jwt_encoder'),
            new Reference('rhapsody_security.jwt_payload_adapter'),
            new Reference('event_dispatcher')), $definition->getArguments());
    }

    public function testPayloadAdapter()
    {
        $container = $this->getContainer('all');

        $this->assertTrue($container->hasDefinition('rhapsody_security.jwt.adapter.payload_adapter.lcobucci'));
        $this->assertEquals('rhapsody_security.jwt.adapter.payload_adapter.lcobucci', (string) $container->getAlias('rhapsody_security.jwt_payload_adapter'));
    }

    public function testPayloadAdapterFromDefaultConfig()
    {
        $container = $this->getContainer('default');

        $this->assertTrue($container->hasDefinition('rhapsody_security.jwt.adapter.payload_adapter.default'));
        $this->assertEquals('rhapsody_security.jwt.adapter.payload_adapter.default', (string) $container->getAlias('rhapsody_security.jwt_payload_adapter'));
    }

    public function testJwtLoginFirewall()
    {
        $container = $this->getContainer('jwt_login_firewall');
        list($listeners, $configs) = $this->getFirewallListenersAndConfiguration($container);

        $this->assertEquals(array(
            array(
                'default', /* firewall name */
                'security.user_checker', /* user checker */
                null,
                true,
                false,
                'foo', /* provider ID/provider key? */
                'default', /* firewall name (or maybe provider key?) */
                null,
                null,
                null,
                array('jwt_login') /* listeners */
            ),
            array(
                'custom_checkpath', /* firewall name */
                'security.user_checker', /* user checker */
                null,
                true,
                false,
                'foo', /* provider ID/provider key? */
                'custom_checkpath', /* firewall name (or maybe provider key?) */
                null,
                null,
                null,
                array('jwt_login') /* listeners */
            ),
            array(
                'custom_credentials', /* firewall name */
                'security.user_checker', /* user checker */
                null,
                true,
                false,
                'foo', /* provider ID/provider key? */
                'custom_credentials', /* firewall name (or maybe provider key?) */
                null,
                null,
                null,
                array('jwt_login') /* listeners */
            ),
            array(
                'full', /* firewall name */
                'security.user_checker', /* user checker */
                null,
                true,
                false,
                'foo', /* provider ID/provider key? */
                'full', /* firewall name (or maybe provider key?) */
                null,
                null,
                null,
                array('jwt_login') /* listeners */
            ),
        ), $configs);

        $this->assertEquals(array(
            array(
                'security.channel_listener',
                'security.context_listener.0',
                'rhapsody_security.authentication.listener.jwt.default',
                'security.access_listener'
            ),
            array(
                'security.channel_listener',
                'security.context_listener.1',
                'rhapsody_security.authentication.listener.jwt.custom_checkpath',
                'security.access_listener'
            ),
            array(
                'security.channel_listener',
                'security.context_listener.2',
                'rhapsody_security.authentication.listener.jwt.custom_credentials',
                'security.access_listener'
            ),
            array(
                'security.channel_listener',
                'security.context_listener.3',
                'rhapsody_security.authentication.listener.jwt.full',
                'security.access_listener'
            ),
        ), $listeners);
    }

    public function testJwtRefreshFirewall()
    {
        $container = $this->getContainer('jwt_refresh_firewall');
        list($listeners, $configs) = $this->getFirewallListenersAndConfiguration($container);

        $this->assertEquals(array(
            array(
                'default', /* firewall name */
                'security.user_checker', /* user checker */
                null,
                true,
                false,
                'foo', /* provider ID/provider key? */
                'default', /* firewall name (or maybe provider key?) */
                null,
                null,
                null,
                array('jwt_login', 'jwt_refresh') /* listeners */
            ),
            array(
                'custom_path', /* firewall name */
                'security.user_checker', /* user checker */
                null,
                true,
                false,
                'foo', /* provider ID/provider key? */
                'custom_path', /* firewall name (or maybe provider key?) */
                null,
                null,
                null,
                array('jwt_login', 'jwt_refresh') /* listeners */
            ),
            array(
                'full', /* firewall name */
                'security.user_checker', /* user checker */
                null,
                true,
                false,
                'foo', /* provider ID/provider key? */
                'full', /* firewall name (or maybe provider key?) */
                null,
                null,
                null,
                array('jwt_login', 'jwt_refresh') /* listeners */
            ),
        ), $configs);

        $this->assertEquals(array(
            array(
                'security.channel_listener',
                'security.context_listener.0',
                'rhapsody_security.authentication.listener.jwt.default',
                'rhapsody_security.authentication.listener.jwt_refresh.default',
                'security.access_listener',
            ),
            array(
                'security.channel_listener',
                'security.context_listener.1',
                'rhapsody_security.authentication.listener.jwt.custom_path',
                'rhapsody_security.authentication.listener.jwt_refresh.custom_path',
                'security.access_listener'
            ),
            array(
                'security.channel_listener',
                'security.context_listener.2',
                'rhapsody_security.authentication.listener.jwt.full',
                'rhapsody_security.authentication.listener.jwt_refresh.full',
                'security.access_listener'
            ),
        ), $listeners);
    }

    /**
     *
     * @param unknown $file
     * @return mixed|\Symfony\Component\DependencyInjection\ContainerBuilder
     */
    protected function getContainer($file)
    {
        $file = sprintf('%s.%s', $file, $this->getFileExtension());

        if (isset(self::$containerCache[$file])) {
            return self::$containerCache[$file];
        }
        $container = new ContainerBuilder();
        $security = new SecurityExtension();
        $rhapsodySecurity = new RhapsodySecurityExtension();
        $container->registerExtension($security);
        $container->registerExtension($rhapsodySecurity);

        $bundle = new RhapsodySecurityBundle();
        $bundle->build($container); // Attach all default factories
        $this->getLoader($container)->load($file);

        $this->compileContainer($container);
        return self::$containerCache[$file] = $container;
    }

    /**
     *
     * @param ContainerBuilder $container
     * @return a tuple of <code>$listeners</code> and <code>$configs</code>
     */
    protected function getFirewallListenersAndConfiguration(ContainerBuilder $container)
    {
        $arguments = $container->getDefinition('security.firewall.map')->getArguments();
        $listeners = array();
        $configs = array();

        foreach (array_keys($arguments[1]) as $contextId) {
            $contextDefinition = $container->getDefinition($contextId);
            $arguments = $contextDefinition->getArguments();
            $listeners[] = array_map(function($ref) {
                return (string) $ref;
            }, $arguments['index_0']);

            $configDefinition = $container->getDefinition($arguments['index_2']);
            $configs[] = array_values($configDefinition->getArguments());
        }
        return [$listeners, $configs];
    }

    /**
     *
     * @param ContainerBuilder $container
     */
    private function compileContainer(ContainerBuilder $container)
    {
        $container->getCompilerPassConfig()->setOptimizationPasses(array());
        $container->getCompilerPassConfig()->setRemovingPasses(array());
        $container->compile();
    }

}