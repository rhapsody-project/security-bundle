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
namespace Rhapsody\SecurityBundle\Tests\DependencyInjection\Security\Factory\Jwt;

use Rhapsody\SecurityBundle\DependencyInjection\Security\Factory\Jwt\JwtTokenExtractorFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;
use PHPUnit\Framework\TestCase;

class JwtTokenExtractorFactoryTest extends TestCase
{

    private function getAuthorizationHeaderTokenExtractorDefinition($name, $prefix)
    {
        $definition = $this->getMockBuilder(Definition::class)
            ->disableOriginalConstructor()
            ->getMock();

        $definition->expects($this->at(0))
            ->method('replaceArgument')
            ->with(0, $prefix)
            ->willReturnSelf();

        $definition->expects($this->at(1))
            ->method('replaceArgument')
            ->with(1, $name)
            ->willReturnSelf();

        return $definition;
    }

    private function getChainTokenExtractorDefition($configuredTokenExtractorsMap)
    {
        $definition = $this->getMockBuilder(Definition::class)
            ->disableOriginalConstructor()
            ->getMock();

        $definition->expects($this->once())
            ->method('replaceArgument')
            ->with(0, $configuredTokenExtractorsMap)
            ->willReturnSelf();

        return $definition;
    }

    private function getContainerBuilder()
    {
        $containerBuilder = $this->getMockBuilder(ContainerBuilder::class)
            ->disableOriginalConstructor()
            ->getMock();
        return $containerBuilder;
    }

    private function getCookieTokenExtractorDefinition($name)
    {
        $definition = $this->getMockBuilder(Definition::class)
            ->disableOriginalConstructor()
            ->getMock();

        $definition->expects($this->once())
            ->method('replaceArgument')
            ->with(0, $name)
            ->willReturnSelf();

        return $definition;
    }

    private function getJsonBodyTokenExtractorDefinition($name)
    {
        $definition = $this->getMockBuilder(Definition::class)
            ->disableOriginalConstructor()
            ->getMock();

        $definition->expects($this->once())
            ->method('replaceArgument')
            ->with(0, $name)
            ->willReturnSelf();

        return $definition;
    }

    private function getQueryParameterTokenExtractorDefinition($name)
    {
        $definition = $this->getMockBuilder(Definition::class)
            ->disableOriginalConstructor()
            ->getMock();

        $definition->expects($this->once())
            ->method('replaceArgument')
            ->with(0, $name)
            ->willReturnSelf();

        return $definition;
    }

    public function testCreateWithNoTokenExtractorsDefined()
    {
        $chainTokenExtractor = $this->getChainTokenExtractorDefition(array());

        $mockContainer = $this->getContainerBuilder();
        $mockContainer->expects($this->once())
            ->method('getDefinition')
            ->with('rhapsody_security.jwt.token_extractor.chain_token_extractor')
            ->willReturn($chainTokenExtractor);

        $config = array();

        $factory = new JwtTokenExtractorFactory();
        $factory->create($mockContainer, $config);
    }

    public function testCreateWithAuthorizationHeaderTokenExtractorEnabled()
    {
        $authorizationHeaderTokenExtractor = $this->getAuthorizationHeaderTokenExtractorDefinition('Authorization', 'Bearer');
        $chainTokenExtractor = $this->getChainTokenExtractorDefition(array(
            new Reference('rhapsody_security.jwt.token_extractor.authorization_header_token_extractor')
        ));

        $mockContainer = $this->getContainerBuilder();
        $mockContainer->expects($this->exactly(2))
            ->method('getDefinition')
            ->withConsecutive(
                ['rhapsody_security.jwt.token_extractor.chain_token_extractor'],
                ['rhapsody_security.jwt.token_extractor.authorization_header_token_extractor'])
            ->willReturnOnConsecutiveCalls($chainTokenExtractor, $authorizationHeaderTokenExtractor);

        $config = array(
            'authorization_header' => array(
                'enabled' => true,
                'name' => 'Authorization',
                'prefix' => 'Bearer'
            )
        );

        $factory = new JwtTokenExtractorFactory();
        $factory->create($mockContainer, $config);
    }

    public function testCreateWithCookieTokenExtractorEnabled()
    {
        $cookieTokenExtractor = $this->getCookieTokenExtractorDefinition('BEARER');
        $chainTokenExtractor = $this->getChainTokenExtractorDefition(array(
            new Reference('rhapsody_security.jwt.token_extractor.cookie_token_extractor')
        ));

        $mockContainer = $this->getContainerBuilder();
        $mockContainer->expects($this->exactly(2))
            ->method('getDefinition')
            ->withConsecutive(
                ['rhapsody_security.jwt.token_extractor.chain_token_extractor'],
                ['rhapsody_security.jwt.token_extractor.cookie_token_extractor'])
            ->willReturnOnConsecutiveCalls($chainTokenExtractor, $cookieTokenExtractor);

        $config = array(
            'cookie' => array(
                'enabled' => true,
                'name' => 'BEARER'
            )
        );

        $factory = new JwtTokenExtractorFactory();
        $factory->create($mockContainer, $config);
    }

    public function testCreateWithJsonBodyTokenExtractorEnabled()
    {
        $jsonBodyTokenExtractor = $this->getJsonBodyTokenExtractorDefinition('token');
        $chainTokenExtractor = $this->getChainTokenExtractorDefition(array(
            new Reference('rhapsody_security.jwt.token_extractor.json_body_token_extractor')
        ));

        $mockContainer = $this->getContainerBuilder();
        $mockContainer->expects($this->exactly(2))
            ->method('getDefinition')
            ->withConsecutive(
                ['rhapsody_security.jwt.token_extractor.chain_token_extractor'],
                ['rhapsody_security.jwt.token_extractor.json_body_token_extractor'])
            ->willReturnOnConsecutiveCalls($chainTokenExtractor, $jsonBodyTokenExtractor);

        $config = array(
            'json_body' => array(
                'enabled' => true,
                'name' => 'token'
            )
        );

        $factory = new JwtTokenExtractorFactory();
        $factory->create($mockContainer, $config);
    }

    public function testCreateWithQueryParameterTokenExtractorEnabled()
    {
        $queryParameterTokenExtractor = $this->getQueryParameterTokenExtractorDefinition('bearer');
        $chainTokenExtractor = $this->getChainTokenExtractorDefition(array(
                new Reference('rhapsody_security.jwt.token_extractor.query_parameter_token_extractor')
        ));

        $mockContainer = $this->getContainerBuilder();
        $mockContainer->expects($this->exactly(2))
            ->method('getDefinition')
            ->withConsecutive(
                ['rhapsody_security.jwt.token_extractor.chain_token_extractor'],
                ['rhapsody_security.jwt.token_extractor.query_parameter_token_extractor'])
            ->willReturnOnConsecutiveCalls($chainTokenExtractor, $queryParameterTokenExtractor);

        $config = array(
            'query_parameter' => array(
                'enabled' => true,
                'name' => 'bearer'
            )
        );

        $factory = new JwtTokenExtractorFactory();
        $factory->create($mockContainer, $config);
    }

    public function testGetKey()
    {
        $factory = new JwtTokenExtractorFactory();
        $this->assertEquals('token_extractors', $factory->getKey());
    }
}