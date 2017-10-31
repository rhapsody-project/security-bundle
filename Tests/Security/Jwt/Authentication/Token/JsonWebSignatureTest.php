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
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Signature\JsonWebSignature;

/**
 *
 * @author    Sean W. Quinn <sean.quinn@extesla.com>
 * @category  Rhapsody SecurityBundle
 * @package   Rhapsody\SecurityBundle\Jwt\Authentication\Token
 * @copyright Rhapsody Project
 * @version   $Id$
 * @since     1.0
 */
class JsonWebSignatureTest extends TestCase
{

    private $goodPayload;

    protected function setUp()
    {
        $this->goodPayload = array(
            'username' => 'jameskirk',
            'exp' => time() + 3600,
            'iat' => time()
        );
    }

    public function testCreateSigned()
    {
        $jws = new JsonWebSignature($token = 'jwt', true);

        $this->assertSame($token, $jws->getToken());
        $this->assertTrue($jws->isSigned());
    }

    public function testCreateUnsigned()
    {
        $jws = new JsonWebSignature($token = 'jwt', false);

        $this->assertSame($token, $jws->getToken());
        $this->assertFalse($jws->isSigned());
    }

    public function testIsExpiredWhenExpirationClaimInPast()
    {
        $payload = $this->goodPayload;
        $payload['exp'] -= 3600;

        $jws = new JsonWebSignature($token = 'jwt', true);
        $jws->update($payload, true);

        $this->assertSame($payload, $jws->getPayload());
        $this->assertFalse($jws->isInvalid());
        $this->assertFalse($jws->isSigned());
        $this->assertFalse($jws->isVerified());
        $this->assertTrue($jws->isExpired());
    }

    public function testIsInvalidWhenIssuedAtClaimInFuture()
    {
        $payload = $this->goodPayload;
        $payload['iat'] += 3600;

        $jws = new JsonWebSignature($token = 'jwt', true);
        $jws->update($payload, true);

        $this->assertSame($payload, $jws->getPayload());
        $this->assertFalse($jws->isExpired());
        $this->assertFalse($jws->isSigned());
        $this->assertFalse($jws->isVerified());
        $this->assertTrue($jws->isInvalid());
    }

    public function testIsInvalidWhenPayloadIsUnverified()
    {
        $jws = new JsonWebSignature($token = 'jwt', true);
        $jws->update($this->goodPayload, false);

        $this->assertSame($this->goodPayload, $jws->getPayload());
        $this->assertFalse($jws->isExpired());
        $this->assertFalse($jws->isVerified());
        $this->assertFalse($jws->isInvalid());
        $this->assertTrue($jws->isSigned());
    }

    public function testIsVerifiedWithGoodPayloadAndVerification()
    {
        $jws = new JsonWebSignature($token = 'jwt', true);
        $jws->update($this->goodPayload, true);

        $this->assertSame($this->goodPayload, $jws->getPayload());
        $this->assertFalse($jws->isInvalid());
        $this->assertFalse($jws->isExpired());
        $this->assertFalse($jws->isSigned());
        $this->assertTrue($jws->isVerified());
    }

    public function testUnverifiedSignatureWithEmptyPayload()
    {
        $jws = new JsonWebSignature($token = 'jwt', true);
        $jws->update($payload = array(), true);

        $this->assertSame($payload, $jws->getPayload());
        $this->assertFalse($jws->isExpired());
        $this->assertFalse($jws->isSigned());
        $this->assertFalse($jws->isVerified());
        $this->assertTrue($jws->isInvalid());
    }
}