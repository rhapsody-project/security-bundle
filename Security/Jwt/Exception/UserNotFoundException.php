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
namespace Rhapsody\SecurityBundle\Security\Jwt\Exception;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * An exception that indicates that the token was missing a required key during
 * the authentication process.
 */
class UserNotFoundException extends AuthenticationException
{
    /**
     * The field name on the token that holds the user identity.
     * @var string
     */
    private $userIdentityFieldName;

    /**
     * The identity (e.g. username) of the user that could not be found.
     * @var string
     */
    private $identity;

    public function __construct($userIdentityFieldName, $identity)
    {
        $this->userIdentityFieldName = $userIdentityFieldName;
        $this->identity = $identity;
    }

    /**
     * {@inheritDoc}
     * @see \Symfony\Component\Security\Core\Exception\AuthenticationException::getMessageKey()
     */
    public function getMessageKey()
    {
        return sprintf('Unable to load user with property "%s" = "%s". If the user identity has changed, you must renew the token. Otherwise, verify that the "rhapsody_security.jwt.claims.identity_claim" configuration option is set correctly.', $this->userIdentityFieldName, $this->identity);
    }
}
