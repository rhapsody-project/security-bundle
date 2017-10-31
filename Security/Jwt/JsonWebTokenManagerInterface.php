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
namespace Rhapsody\SecurityBundle\Security\Jwt;

use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebTokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

interface JsonWebTokenManagerInterface
{

    /**
     * Creates and returns a JWT refresh token, which can be used to
     * reauthenticate users whose tokens have expired.
     *
     * @return JwtRefreshToken The JWT refresh token.
     */
    function createRefreshToken();

    /**
     * Creates a JWT token that can be used for authentication.
     *
     * @param UserInterface $user The user
     * @return JsonWebTokenInterface
     */
    function createToken(UserInterface $user);

    /**
     * Decodes a JWT token and returns the token's payload. If an error occurs
     * during decoding the boolean value <code>false</code> will be returned.
     *
     * @param JsonWebTokenInterface|string $token The JWT token to be decoded.
     * @return array|boolean The JWT token payload; otherwise <code>false</code>
     *     if an error occurs during decoding.
     */
    function decode($token);

    /**
     * Return the <code>ClaimInterface</code> from the collection of registered
     * <code>$claims</code> that has the identifier <code>$claim</code>.
     *
     * @param string $claim the claim identifier.
     * @return \Rhapsody\SecurityBundle\Security\Jwt\ClaimInterface
     */
    function getClaim($claim);

    /**
     *
     * @return \Rhapsody\SecurityBundle\Security\Jwt\ClaimInterface[]
     */
    function getClaims();

    /**
     *
     */
    function getIdentityClaim();

    /**
     *
     * @param JsonWebTokenInterface $jwt
     */
    function getUserIdentityFromToken(JsonWebTokenInterface $jwt);

    /**
     *
     * @param array $payload
     */
    function getUserIdentityFromPayload(array $payload = array());

//     /**
//      * @param string $refreshToken
//      *
//      * @return RefreshTokenInterface
//      */
//     public function get($refreshToken);

//     /**
//      * @param string $username
//      *
//      * @return RefreshTokenInterface
//      */
//     public function getLastFromUsername($username);

//     /**
//      * @param RefreshTokenInterface $refreshToken
//      */
//     public function save(RefreshTokenInterface $refreshToken);

//     /**
//      * @param RefreshTokenInterface $refreshToken
//      */
//     public function delete(RefreshTokenInterface $refreshToken);

//     /**
//      * @return RefreshTokenInterface[]
//      */
//     public function revokeAllInvalid();

//     /**
//      * Returns the user's fully qualified class name.
//      *
//      * @return string
//      */
//     public function getClass();
}