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
namespace Rhapsody\SecurityBundle\Tests\Security\Jwt\Encoder;

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Signature\JsonWebSignature;
use Rhapsody\SecurityBundle\Security\Jwt\Encoder\DefaultEncoder;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\JwtDecodeFailureException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\JwtEncodeFailureException;

abstract class AbstractEncoderTest extends TestCase
{

    /**
     * @var string
     */
    protected static $jwsProviderClass;

    /**
     * @var string
     */
    protected static $encoderClass;

    /**
     *
     * @return PHPUnit_Framework_MockObject_MockObject
     */
    private function getJwsProviderMock()
    {
        $mock = $this->getMockBuilder(static::$jwsProviderClass)
            ->disableOriginalConstructor()
            ->getMock();
        return $mock;
    }

    public function testDecodeFromExpiredJsonWebSignature()
    {
        $payload = array(
            'username' => 'jameskirk',
            'exp' => time() - 3600
        );
        $jws = new JsonWebSignature('jwt', true);
        $jws->update($payload, true);

        $jwsProvider = $this->getJwsProviderMock();
        $jwsProvider->expects($this->once())->method('load')->willReturn($jws);

        $this->expectException(JwtDecodeFailureException::class);
        $this->expectExceptionMessage('Expired JWT Token');

        $encoder = new static::$encoderClass($jwsProvider);
        $encoder->decode('jwt');
    }

    public function testDecodeWithInvalidIssudAtClaimInPayload()
    {
        $payload = array(
            'username' => 'jameskirk',
            'exp' => time() + 3600,
            'iat' => time() + 3600
        );
        $jws = new JsonWebSignature('jwt', true);
        $jws->update($payload, true);

        $jwsProvider = $this->getJwsProviderMock();
        $jwsProvider->expects($this->once())->method('load')->willReturn($jws);

        $this->expectException(JwtDecodeFailureException::class);
        $this->expectExceptionMessage('Invalid JWT Token');

        $encoder = new DefaultEncoder($jwsProvider);
        $encoder->decode('jwt');
    }

    public function testDecodeFromUnverifiedJsonWebSignature()
    {
        $payload = array();

        $jws = new JsonWebSignature('jwt', true);
        $jws->update($payload, false);

        $jwsProvider = $this->getJwsProviderMock();
        $jwsProvider->expects($this->once())->method('load')->willReturn($jws);

        $this->expectException(JwtDecodeFailureException::class);

        $encoder = new static::$encoderClass($jwsProvider);
        $encoder->decode('jwt');
    }

    public function testDecodeFromValidJsonWebSignature()
    {
        $payload = array(
            'username' => 'jameskirk',
            'exp' => time() + 3600,
        );

        $jws = new JsonWebSignature('jwt', true);
        $jws->update($payload, true);

        $jwsProvider = $this->getJwsProviderMock();
        $jwsProvider->expects($this->once())->method('load')->willReturn($jws);

        $encoder = new static::$encoderClass($jwsProvider);
        $actual = $encoder->decode('jwt');
        $this->assertSame($payload, $actual);
    }

    public function testEncodeFromUnsignedJsonWebSignature()
    {
        $jws = new JsonWebSignature('jwt', false);

        $jwsProvider = $this->getJwsProviderMock();
        $jwsProvider->expects($this->once())->method('create')->willReturn($jws);

        $this->expectException(JwtEncodeFailureException::class);

        $encoder = new static::$encoderClass($jwsProvider);
        $encoder->encode(array());
    }

    public function testEncodeFromValidJsonWebSignature()
    {
        $jws = new JsonWebSignature('jwt', true);

        $jwsProvider = $this->getJwsProviderMock();
        $jwsProvider->expects($this->once())->method('create')->willReturn($jws);

        $encoder = new static::$encoderClass($jwsProvider);
        $actual = $encoder->encode(array());
        $this->assertSame('jwt', $actual);
    }

}
