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
namespace Rhapsody\SecurityBundle\Security\Guard\Authenticator;

use Rhapsody\SecurityBundle\RhapsodySecurityEvents;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebToken;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebTokenInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtAuthenticatedEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtExpiredEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtInvalidEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtNotFoundEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\ExpiredTokenException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\InvalidTokenException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\JwtDecodeFailureException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\MissingTokenException;
use Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Response\JwtAuthenticationFailureResponse;
use Rhapsody\SecurityBundle\Security\Jwt\TokenExtractor\TokenExtractorInterface;
use Rhapsody\SecurityBundle\Security\Jwt\User\JwtTokenUserProvider;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\GuardAuthenticatorInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;

/**
 * An implementation of the {@link GuardAuthenticatorInterface} for JSON Web
 * Tokens (JWTs).
 *
 * @author sean.quinn
 */
class JwtTokenAuthenticator implements GuardAuthenticatorInterface
{

    /**
     *
     * @var EventDispatcherInterface
     */
    private $eventDispatcher;

    /**
     *
     * @var JsonWebTokenManagerInterface
     */
    private $jsonWebTokenManager;

    /**
     *
     * @var \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface
     */
    private $preAuthenticationTokenStorage;

    /**
     *
     * @var \Rhapsody\SecurityBundle\Security\Jwt\TokenExtractor\TokenExtractorInterface
     */
    private $tokenExtractor;

    /**
     *
     * @param JsonWebTokenManagerInterface $jsonWebTokenManager
     * @param EventDispatcherInterface $eventDispatcher
     */
    public function __construct(JsonWebTokenManagerInterface $jsonWebTokenManager, EventDispatcherInterface $eventDispatcher, TokenExtractorInterface $tokenExtractor)
    {
        $this->jsonWebTokenManager = $jsonWebTokenManager;
        $this->eventDispatcher = $eventDispatcher;
        $this->tokenExtractor = $tokenExtractor;
        $this->preAuthenticationTokenStorage = new TokenStorage();
    }

    /**
     *
     * {@inheritdoc}
     *
     * @throws \RuntimeException If there is no pre-authenticated token
     *         previously stored
     */
    public function createAuthenticatedToken(UserInterface $user, $providerKey)
    {
        /** @var $preAuthToken \Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebTokenInterface */
        $preAuthToken = $this->preAuthenticationTokenStorage->getToken();

        if (null === $preAuthToken) {
            throw new \RuntimeException('Unable to return an authenticated token since there is no pre authentication token.');
        }

        $authToken = new JsonWebToken($user, $preAuthToken->getCredentials(), $providerKey, $user->getRoles());
        $authToken->setPayload($preAuthToken->getPayload());

        $this->eventDispatcher->dispatch(RhapsodySecurityEvents::JWT_AUTHENTICATED, new JwtAuthenticatedEvent($authToken->getPayload(), $authToken));
        $this->preAuthenticationTokenStorage->setToken(null);

        return $authToken;
    }

    /**
     * Gets the authentication credentials as a decoded JWT token, extracted
     * from the request and returns them as a pre-authentication token, e.g.
     * <code>JsonWebToken</code>.
     */
    public function getCredentials(Request $request)
    {
        $tokenExtractor = $this->getTokenExtractor();

        if (! $tokenExtractor instanceof TokenExtractorInterface) {
            throw new \RuntimeException(sprintf('Method "%s::getTokenExtractor()" must return an instance of "%s".', __CLASS__, TokenExtractorInterface::class));
        }

        $rawToken = $tokenExtractor->extract($request);
        if (false === $rawToken) {
            return;
        }

        // **
        // Construct the JsonWebToken from the raw token; we'll populate the
        // decoded payload immediately following this. The user is set when
        // we create the authenticated token. [SWQ]
        $jwt = JsonWebToken::fromToken($rawToken);

        try {
            $payload = $this->jsonWebTokenManager->decode($jwt);
            if (! $payload) {
                throw new InvalidTokenException('Invalid JWT Token');
            }
            $jwt->setPayload($payload);
        }
        catch ( JwtDecodeFailureException $ex ) {
            if (JwtDecodeFailureException::EXPIRED_TOKEN === $ex->getReason()) {
                throw new ExpiredTokenException();
            }
            throw new InvalidTokenException('Invalid JWT Token', 0, $ex);
        }

        return $jwt;
    }

    /**
     * Returns an user object loaded from a JWT token.
     *
     * {@inheritdoc}
     *
     * @param JsonWebTokenInterface Implementation of the (Security)
     *        TokenInterface
     * @throws \InvalidArgumentException If preAuthToken is not of the good type
     * @throws InvalidPayloadException If the user identity field is not a key
     *         of the payload
     * @throws UserNotFoundException If no user can be loaded from the given
     *         token
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        if (!$credentials instanceof JsonWebTokenInterface) {
            throw new \InvalidArgumentException(sprintf('The first argument of the "%s()" method must be an instance of "%s".', __METHOD__, JsonWebTokenInterface::class));
        }

        $payload = $credentials->getPayload();
        $identity = $this->jsonWebTokenManager->getUserIdentityFromToken($credentials);
        try {
            $user = $this->loadUser($userProvider, $payload, $identity);
        }
        catch (UsernameNotFoundException $ex) {
            $identityClaim = $this->jsonWebTokenManager->getIdentityClaim();
            throw new UserNotFoundException($identityClaim, $identity);
        }

        $this->preAuthenticationTokenStorage->setToken($credentials);
        return $user;
    }

    /**
     *
     * {@inheritdoc}
     *
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $authException)
    {
        $response = new JwtAuthenticationFailureResponse($authException->getMessageKey());

        if ($authException instanceof ExpiredTokenException) {
            $event = new JwtExpiredEvent($authException, $response);
            $this->eventDispatcher->dispatch(RhapsodySecurityEvents::JWT_EXPIRED, $event);
        }
        else {
            $event = new JwtInvalidEvent($authException, $response);
            $this->eventDispatcher->dispatch(RhapsodySecurityEvents::JWT_INVALID, $event);
        }

        return $event->getResponse();
    }

    /**
     *
     * {@inheritdoc}
     *
     * @see \Symfony\Component\Security\Guard\GuardAuthenticatorInterface::onAuthenticationSuccess()
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        // TODO: Implement non-API access for authentication success redirects?
        return;
    }

    /**
     *
     * {@inheritdoc}
     *
     * @return JWTAuthenticationFailureResponse
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $exception = new MissingTokenException('JWT Token not found', 0, $authException);
        $event = new JwtNotFoundEvent($exception, new JwtAuthenticationFailureResponse($exception->getMessageKey()));

        $this->eventDispatcher->dispatch(RhapsodySecurityEvents::JWT_NOT_FOUND, $event);

        return $event->getResponse();
    }

    /**
     *
     * {@inheritdoc}
     *
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }

    /**
     *
     * {@inheritdoc}
     *
     * @see \Symfony\Component\Security\Guard\GuardAuthenticatorInterface::supportsRememberMe()
     */
    public function supportsRememberMe()
    {
        // NB: The JWT authentication token doesn't implicitly support remember
        // me auth
        return false;
    }

    /**
     * Gets the token extractor to be used for retrieving a JWT token in the
     * current request.
     * Override this method for adding/removing extractors to the chain one or
     * returning a different {@link TokenExtractorInterface} implementation.
     *
     * @return TokenExtractorInterface
     */
    protected function getTokenExtractor()
    {
        return $this->tokenExtractor;
    }

    /**
     * Loads the user to authenticate.
     *
     * @param UserProviderInterface $userProvider An user provider
     * @param array $payload The token payload
     * @param string $identity The key from which to retrieve the user
     *        "username"
     * @return UserInterface
     */
    protected function loadUser(UserProviderInterface $userProvider, array $payload, $identity)
    {
        if ($userProvider instanceof JwtTokenUserProvider) {
            return $userProvider->loadUserByUsername($identity, $payload);
        }

        return $userProvider->loadUserByUsername($identity);
    }
}