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
namespace Rhapsody\SecurityBundle\Security\Jwt\Encoder;

use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Provider\JwsProviderInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\JwtDecodeFailureException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\JwtEncodeFailureException;

/**
 * Default Json Web Token encoder/decoder.
 *
 * @author Robin Chalas <robin.chalas@gmail.com>
 */
class DefaultEncoder implements JwtEncoderInterface
{
    /**
     * @var JWSProviderInterface
     */
    protected $jwsProvider;

    /**
     * @param JWSProviderInterface $jwsProvider
     */
    public function __construct(JwsProviderInterface $jwsProvider)
    {
        $this->jwsProvider = $jwsProvider;
    }

    /**
     * {@inheritdoc}
     */
    public function encode(array $payload)
    {
        try {
            $jws = $this->jwsProvider->create($payload);
        }
        catch (\InvalidArgumentException $e) {
            throw new JwtEncodeFailureException(JwtEncodeFailureException::INVALID_CONFIG, 'An error occured while trying to encode the JWT token. Please verify your configuration (private key/passphrase)', $e);
        }

        if (!$jws->isSigned()) {
            throw new JwtEncodeFailureException(JwtEncodeFailureException::UNSIGNED_TOKEN, 'Unable to create a signed JWT from the given configuration.');
        }

        return $jws->getToken();
    }

    /**
     * {@inheritdoc}
     */
    public function decode($token)
    {
        try {
            $jws = $this->jwsProvider->load($token);
        }
        catch (\Exception $e) {
            throw new JwtDecodeFailureException(JwtDecodeFailureException::INVALID_TOKEN, 'Invalid JWT Token', $e);
        }

        if ($jws->isInvalid()) {
            throw new JwtDecodeFailureException(JwtDecodeFailureException::INVALID_TOKEN, 'Invalid JWT Token');
        }

        if ($jws->isExpired()) {
            throw new JwtDecodeFailureException(JwtDecodeFailureException::EXPIRED_TOKEN, 'Expired JWT Token');
        }

        if (!$jws->isVerified()) {
            throw new JwtDecodeFailureException(JwtDecodeFailureException::UNVERIFIED_TOKEN, 'Unable to verify the given JWT through the given configuration. If the "rhapsody_security.jwt_encoder" encryption options have been changed since your last authentication, please renew the token. If the problem persists, verify that the configured keys/passphrase are valid.');
        }

        return $jws->getPayload();
    }
}
