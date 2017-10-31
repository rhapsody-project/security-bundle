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
namespace Rhapsody\SecurityBundle\Tests\Security\Jwt\Authentication\Token;

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebToken;
use Symfony\Component\Security\Core\Role\Role;

class JsonWebTokenTest extends TestCase
{

    public function testConstructorWithUsernameAndRawTokenAndRoles()
    {
        $jwt = new JsonWebToken('foo', 'bar', 'key', array('ROLE_FOO'));
        $this->assertTrue($jwt->isAuthenticated());
        $this->assertEquals(array(new Role('ROLE_FOO')), $jwt->getRoles());
        $this->assertEquals('bar', $jwt->getRawToken());
        $this->assertEquals('key', $jwt->getProviderKey());
    }

    public function testConstructorWithUsernameAndRawTokenButNoRoles()
    {
        $jwt = new JsonWebToken('foo', 'bar', 'key');
        $this->assertTrue($jwt->isAuthenticated());
        $this->assertEmpty($jwt->getRoles());
        $this->assertEquals('bar', $jwt->getRawToken());
        $this->assertEquals('key', $jwt->getProviderKey());
    }

    public function testConstructorWithUsernameAndProviderKeyOnly()
    {
        $jwt = new JsonWebToken('foo', null, 'key');
        $this->assertTrue($jwt->isAuthenticated());
        $this->assertEmpty($jwt->getRoles());
        $this->assertNull($jwt->getRawToken());
        $this->assertEquals('key', $jwt->getProviderKey());
    }

    /**
     * @expectedException \LogicException
     */
    public function testSetAuthenticatedToTrue()
    {
        $jwt = new JsonWebToken('foo', 'bar', 'key');
        $jwt->setAuthenticated(true);
    }

    public function testSetAuthenticatedToFalse()
    {
        $jwt = new JsonWebToken('foo', 'bar', 'key');
        $jwt->setAuthenticated(false);
        $this->assertFalse($jwt->isAuthenticated());
    }

    public function testEraseCredentials()
    {
        $jwt = new JsonWebToken('foo', 'bar', 'key');
        $jwt->eraseCredentials();
        $this->assertEquals('', $jwt->getCredentials());
    }

    public function testToString()
    {
        $jwt = new JsonWebToken('foo', '', 'foo', array('A', 'B'));
        $this->assertEquals('JsonWebToken(user="foo", authenticated=true, roles="A, B")', (string) $jwt);
    }
}
