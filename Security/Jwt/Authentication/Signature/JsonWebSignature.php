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
namespace Rhapsody\SecurityBundle\Security\Jwt\Authentication\Signature;

use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Signature\JsonWebSignatureInterface;

/**
 *
 * @author    Sean W. Quinn <sean.quinn@extesla.com>
 * @category  Rhapsody SecurityBundle
 * @package   Rhapsody\SecurityBundle\Jwt\Authentication\Signature
 * @copyright Rhapsody Project
 * @version   $Id$
 * @since     1.0
 */
class JsonWebSignature implements JsonWebSignatureInterface
{

    /**
     * @var string
     */
    const EXPIRED = 'expired';

    /**
     *
     * @var string
     */
    const INVALID = 'invalid';

    /**
     *
     * @var string
     */
    const SIGNED = 'signed';

    /**
     *
     * @var string
     */
    const VERIFIED = 'verified';

    /**
     * The payload
     * @var unknown
     */
    private $payload;

    private $state;

    /**
     * The JSON Web Token.
     * @var JsonWebToken
     */
    private $token;

    public function __construct($token, $signed)
    {
        if (true === $signed) {
            $this->state = self::SIGNED;
        }
        $this->token = $token;
    }

    /**
     * Ensures that the signature is not expired.
     */
    private function checkExpiration()
    {
        if (!isset($this->payload['exp']) || !is_numeric($this->payload['exp'])) {
            return $this->state = self::INVALID;
        }
        if (0 <= (new \DateTime())->format('U') - $this->payload['exp']) {
            $this->state = self::EXPIRED;
        }
    }
    /**
     * Ensures that the iat claim is not in the future.
     */
    private function checkIssuedAt()
    {
        if (isset($this->payload['iat']) && (int) $this->payload['iat'] > time()) {
            return $this->state = self::INVALID;
        }
    }

    public function getPayload()
    {
        return $this->payload;
    }

    public function getState()
    {
        return $this->state;
    }

    public function getToken()
    {
        return $this->token;
    }

    public function isExpired()
    {
        $this->checkExpiration();
        return self::EXPIRED === $this->state;
    }

    public function isInvalid()
    {
        return self::INVALID === $this->state;
    }

    public function isSigned()
    {
        return self::SIGNED === $this->state;
    }

    public function isVerified()
    {
        return self::VERIFIED === $this->state;
    }

    public function update(array $payload, $verified)
    {
        $this->payload = $payload;
        if (true === $verified) {
            $this->state = self::VERIFIED;
        }
        $this->checkIssuedAt();
        $this->checkExpiration();
    }

}