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
namespace Rhapsody\SecurityBundle\Tests\Security\Jwt\Authentication\Provider;

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Signature\JsonWebSignature;

/**
 *
 * @author sean.quinn
 */
abstract class AbstractJwsProviderTest extends TestCase
{
    protected static $privateKey = '
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,ED625A98A40504785D6E86F30ED00968

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
-----END RSA PRIVATE KEY-----
';

    protected static $publicKey = '
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwW3xC2SrZy8egtlPzo3/
HsLUTjrxMt7+iSGSWU8zBDuVeC9I8mBpEAHNUmNtByQT/IdeylA2HdbL2GEARqdO
4l/JLJMnY5TUXuATyHom3FSoHzCIb/E8PJKQ9tsfXV4hL4O+lNAseNneA5ekhk6D
3RrILqb4JyLOrFg6LwOmYien/5MgwKiU3X2a1L1U9bRxrgB9EZIf+rSsvkVU49IP
XVO0e0yy8r0XC5UqYGHLqZFILWIHczRHav4q+atxwIhUhVcjC4ldrDt8KqS+87Mk
3dL1rtVhFw9KiA1PM1f/cDMBqhFIbqr/a9eW54nxvad3VLtWEbqzwiV20fXPNutg
r1+IuPoGjEQx4e3DEarJ1pfKd2R2UDqY8V0oX9bOY8Stye4CzwqPTF3gu4/9azL0
nDi9UTjW6lif4S0kowlJ0E3aeIcMt9NPZiFzDQTc2AA41rIiKQfU/Lolv8qS7PgC
Zz7O5PachFwjUDvcZ6wcqT5zAuiGsMbVkWxXthfgGar74aNe3eTFBSlCnG2keD0K
XUXOIoNAxR8fKsmyiJTfCXlP2CBnff6/mVHD1uWMauvIQXJieli+ArLUSHdymt3s
aJKYflXf+fUNs+xK/BWVDSOQBUCWOuIOHzmoC92ZJLY+E1MtEfpDNzxIL0QQQHxA
RGZSs1v9jIIE4sNn4b0N9LECAwEAAQ==
-----END PUBLIC KEY-----
';

    protected static $providerClass;
    protected static $keyLoaderClass;

    /**
     * Tests to create a signed JWT Token.
     */
    public function testCreate()
    {
        $keyLoaderMock = $this->getKeyLoaderMock();
        $keyLoaderMock->expects($this->once())
            ->method('loadKey')
            ->with('private')
            ->willReturn(static::$privateKey);
        $keyLoaderMock->expects($this->once())
            ->method('getPassphrase')
            ->willReturn('to boldly go...');

        $payload = ['username' => 'jameskirk'];

        /** @var \Rhapsody\SecurityBundle\Security\Jwt\Authentication\Provider\JwsProviderInterface */
        $jwsProvider = new static::$providerClass($keyLoaderMock, 'openssl', 'RS384', 3600);

        $actual = $jwsProvider->create($payload);
        $this->assertInstanceOf(JsonWebSignature::class, $actual);

        return $actual->getToken();
    }

    /**
     * Tests to verify the signature of a valid given JWT Token.
     * @depends testCreate
     */
    public function testLoad($jwt)
    {
        $keyLoaderMock = $this->getKeyLoaderMock();
        $keyLoaderMock->expects($this->once())
            ->method('loadKey')
            ->with('public')
            ->willReturn(static::$publicKey);

        $jwsProvider = new static::$providerClass($keyLoaderMock, 'openssl', 'RS384', 3600);
        $actual = $jwsProvider->load($jwt);
        $this->assertInstanceOf(JsonWebSignature::class, $actual);

        $payload = $actual->getPayload();
        $this->assertTrue(isset($payload['exp']));
        $this->assertTrue(isset($payload['iat']));
        $this->assertTrue(isset($payload['username']));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The algorithm "wrongAlgorithm" is not supported
     */
    public function testInvalidsignatureAlgorithm()
    {
        new static::$providerClass($this->getKeyLoaderMock(), 'openssl', 'wrongAlgorithm', 3600);
    }

    private function getKeyLoaderMock()
    {
        return $this->getMockBuilder(static::$keyLoaderClass)
            ->disableOriginalConstructor()
            ->getMock();
    }
}
