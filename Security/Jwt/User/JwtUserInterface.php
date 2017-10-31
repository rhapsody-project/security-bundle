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
namespace Rhapsody\SecurityBundle\Security\Jwt\User;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * A contract that reflects a self-contained <code>UserInterface</code> that
 * can be generated entirely from a JWT Token.
 *
 * The JSON Web Token specification states that a JWT is self-contained, and
 * that "[the] payload contains all the required information about the user,
 * avoiding the need to query the database more than once."
 *
 * <strong>Proceed with caution!</strong> This interface provides functionality
 * similar to the resolution of in-memory users, in that it can resolve a
 * user object without having to query a persistence layer. While this should
 * be fine, given that the JWTs are signed and verified with each request, it
 * may be insufficient for your application to use a user who has been resolved
 * in this manner.
 *
 * @author sean.quinn
 */
interface JwtUserInterface extends UserInterface
{

    /**
     * Creates a new instance of this user with <code>$username</code> from a
     * given JSON Web Token <code>$payload</code>.
     *
     * @param string $username The username.
     * @param array $payload The payload.
     * @return JwtUserInterface The resolved user.
     */
    static function createFromPayload($username, array $payload);

}