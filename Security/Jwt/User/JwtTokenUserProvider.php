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
use Symfony\Component\Security\Core\User\UserProviderInterface;

class JwtTokenUserProvider implements UserProviderInterface
{
    private $class;
    private $cache = [];

    /**
     *
     * @param string $class The {@link JWTUserInterface} implementation FQCN for
     *        which to provide instances
     */
    public function __construct($class)
    {
        $this->class = $class;
    }


    /**
     * {@inheritDoc}
     *
     * @param array $payload The JWT payload from which to create an instance
     * @return mixed
     * @see \Symfony\Component\Security\Core\User\UserProviderInterface::loadUserByUsername()
     */
    public function loadUserByUsername($username, array $payload = [])
    {
        $class = $this->class;

        if (isset($this->cache[$username])) {
            return $this->cache[$username];
        }

        return $this->cache[$username] = $class::createFromPayload($username, $payload);
    }

    /**
     * {@inheritDoc}
     * @see \Symfony\Component\Security\Core\User\UserProviderInterface::supportsClass()
     */
    public function supportsClass($class)
    {
        return $class === $this->class || (new \ReflectionClass($class))->implementsInterface(JWTUserInterface::class);
    }

    /**
     * {@inheritDoc}
     * @see \Symfony\Component\Security\Core\User\UserProviderInterface::refreshUser()
     */
    public function refreshUser(UserInterface $user)
    {
        // noop
    }
}