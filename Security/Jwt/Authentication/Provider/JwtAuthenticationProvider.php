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
namespace Rhapsody\SecurityBundle\Security\Jwt\Authentication\Provider;

use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebTokenInterface;
use Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManager;
use Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class JwtAuthenticationProvider implements AuthenticationProviderInterface
{
    private $jsonWebTokenManager;
    private $providerKey;
    private $userChecker;
    private $userProvider;

    /**
     * Constructor.
     *
     * @param UserProviderInterface $userProvider The associated user provider
     *     interface.
     * @param UserCheckerInterface $userChecker The associated user checker
     *     interface.
     * @param JsonWebTokenManagerInterface $jsonWebTokenManager The JSON web
     *     token manager interface.
     * @param string $providerKey A provider secret
     */
    public function __construct(UserProviderInterface $userProvider, UserCheckerInterface $userChecker, $providerKey, JsonWebTokenManagerInterface $jsonWebTokenManager)
    {
        $this->userProvider = $userProvider;
        $this->userChecker = $userChecker;
        $this->jsonWebTokenManager = $jsonWebTokenManager;
        $this->providerKey = $providerKey;
    }

    /**
     *
     * {@inheritdoc}
     *
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            return;
        }

        $username = $this->jsonWebTokenManager->getUserIdentityFromToken($token);
        try {
            $user = $this->retrieveUser($username, $token);
        }
        catch (UsernameNotFoundException $ex) {
            // TODO:
            $ex->setUsername($username);
            throw $ex;
        }

        try {
            // TODO: We only need this in a try-catch if we potentially want to
            //       trap user not found exceptions in a BadCredentialsException
            //       wrapper--useful for not leaking user information to
            //       possible attackers.
            $this->userChecker->checkPreAuth($user);
        }
        catch (BadCredentialsException $ex) {
            // TODO:
            throw $ex;
        }

        $authenticatedToken = $this->jsonWebTokenManager->createToken($user);
        return $authenticatedToken;
    }

    protected function retrieveUser($username, TokenInterface $token)
    {
        $user = $token->getUser();
        if ($user instanceof UserInterface) {
            return $user;
        }

        try {
            $user = $this->userProvider->loadUserByUsername($username);
            if (!$user instanceof UserInterface) {
                throw new AuthenticationServiceException('The user provider must return a UserInterface object.');
            }
            return $user;
        }
        catch (UsernameNotFoundException $ex) {
            $ex->setUsername($username);
            throw $ex;
        }
        catch (\Exception $ex) {
            $e = new AuthenticationServiceException($ex->getMessage(), 0, $ex);
            $ex->setToken($token);
            throw $ex;
        }
    }

    /**
     * {@inheritdoc}
     * @see \Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface::supports()
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof JsonWebTokenInterface && $token->getProviderKey() === $this->providerKey;
    }
}
