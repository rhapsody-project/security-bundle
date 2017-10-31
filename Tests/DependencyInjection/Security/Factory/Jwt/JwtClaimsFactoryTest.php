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

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\DependencyInjection\Security\Factory\Jwt\JwtClaimsFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

class JwtClaimsFactoryTest extends TestCase
{

    public function testCreateWhenNoClaimsDefined()
    {
        $jwtManagerDefition = $this->createMock(Definition::class);
        $jwtManagerDefition->expects($this->never())
            ->method('addMethodCall');

        $mockContainer = $this->getContainerBuilder();
        $mockContainer->expects($this->once())
            ->method('getDefinition')
            ->willReturn($jwtManagerDefition);

        $config = array('claims' => array());

        $jwtClaimsFactory = new JwtClaimsFactory();
        $jwtClaimsFactory->create($mockContainer, $config);
    }

    public function testCreateWhenOneClaimsDefined()
    {
        $jwtClaimDefition = $this->createMock(Definition::class);
        $jwtClaimDefition->expects($this->once())
            ->method('setArguments')
            ->with(array('foo', 'bar', true));

        $jwtManagerDefition = $this->createMock(Definition::class);
        $jwtManagerDefition->expects($this->once())
            ->method('addMethodCall')
            ->with('addClaim', array('foo', new Reference('rhapsody_security.jwt.claims.claim_foo')));

        $mockContainer = $this->getContainerBuilder();

        $mockContainer->expects($this->once())
            ->method('getDefinition')
            ->willReturn($jwtManagerDefition);

        $mockContainer->expects($this->once())
            ->method('setDefinition')
            ->with('rhapsody_security.jwt.claims.claim_foo', $this->isInstanceOf(Definition::class))
            ->willReturn($jwtClaimDefition);

        $config = array('claims' => array(
            'foo' => array('name' => 'foo', 'property' => 'bar', 'required' => true)
        ));

        $jwtClaimsFactory = new JwtClaimsFactory();
        $jwtClaimsFactory->create($mockContainer, $config);
    }

    public function testGetKey()
    {
        $jwtClaimsFactory = new JwtClaimsFactory();
        $this->assertEquals('claims', $jwtClaimsFactory->getKey());
    }

    private function getContainerBuilder()
    {
        $containerBuilder = $this->getMockBuilder(ContainerBuilder::class)
            ->disableOriginalConstructor()
            ->getMock();
        return $containerBuilder;
    }

}