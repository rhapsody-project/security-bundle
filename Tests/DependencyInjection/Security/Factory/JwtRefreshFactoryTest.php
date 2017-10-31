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
use Rhapsody\SecurityBundle\DependencyInjection\Security\Factory\JwtRefreshFactory;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;

class JwtRefreshFactoryTest extends TestCase
{

    protected function getChild($object, $name)
    {
        $children = $this->getField($object, 'children');
        if (!isset($children[$name])) {
            $this->fail(sprintf('Unable to find child with key: %s in node definition.', $name));
        }
        return $children[$name];
    }

    protected function getField($object, $field)
    {
        $reflection = new \ReflectionProperty($object, $field);
        $reflection->setAccessible(true);

        return $reflection->getValue($object);
    }

    public function testAddConfiguration()
    {
        $node = new ArrayNodeDefinition('jwt_refresh');
        $factory = new JwtRefreshFactory();
        $factory->addConfiguration($node);

        $this->assertCount(5, $this->getField($node, 'children'));

        $actual = $this->getChild($node, 'path');
        $this->assertEquals('/token_refresh', $this->getField($actual, 'defaultValue'));
    }

    public function testGetKey()
    {
        $factory = new JwtRefreshFactory();
        $this->assertEquals('jwt-refresh', $factory->getKey());
    }

    public function testGetPosition()
    {
        $factory = new JwtRefreshFactory();
        $this->assertEquals('remember_me', $factory->getPosition());
    }

}