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
namespace Rhapsody\SecurityBundle\Security\Jwt\RememberMe;

use Psr\Log\LoggerInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebToken;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\ExpiredTokenException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\InvalidTokenException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\JwtDecodeFailureException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\MissingTokenException;
use Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface;
use Rhapsody\SecurityBundle\Security\Jwt\TokenExtractor\TokenExtractorInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\RememberMe\RememberMeServicesInterface;

/**
 * An abstract implementation of shared JSON Web Token (JWT) remember me
 * functionality implementing the <code>RememberMeServicesInterface</code>.
 *
 * In addition to the <code>RememberMeServicesInterface</code> this base class
 * also implement <code>JwtRememberMeServicesInterface</code> which brands all
 * derived services as JWT-specific.
 *
 * @author sean.quinn
 */
abstract class AbstractJwtRememberMeServices implements RememberMeServicesInterface, JwtRememberMeServicesInterface
{

    /**
     * The JSON Web Token (JWT) manager.
     * @var \Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface
     */
    protected $jsonWebTokenManager;

    /**
     * The logger.
     * @var \Psr\Log\LoggerInterface
     */
    protected $logger;

    /**
     * The provider key.
     * @var string
     */
    protected $providerKey;

    /**
     * The token extractor.
     * @var \Rhapsody\SecurityBundle\Security\Jwt\TokenExtractor\TokenExtractorInterface
     */
    protected $tokenExtractor;

    /**
     * The [default] user provider that will be used to look up a user by his
     * username.
     *
     * @var \Symfony\Component\Security\Core\User\UserProviderInterface
     */
    protected $userProvider;

    /**
     * The collection of user providers.
     * @var array
     */
    private $userProviders;

    public function __construct(UserProviderInterface $userProvider, TokenExtractorInterface $tokenExtractor, JsonWebTokenManagerInterface $jsonWebTokenManager, $providerKey, array $options = array(), LoggerInterface $logger = null)
    {
        $this->jsonWebTokenManager = $jsonWebTokenManager;
        $this->providerKey = $providerKey;
        $this->tokenExtractor = $tokenExtractor;
        $this->userProvider = $userProvider;
        $this->logger = $logger;
    }


    final public function autoLogin(Request $request)
    {
        if (null === $token = $this->resolveToken($request)) {
            return;
        }

        try {
            $rawToken = $token->getCredentials();
            $payload = $this->decodePayload($rawToken);
            $token->setPayload($payload);

            $user = $this->processAutoLoginToken($payload, $request);
            if (!$user instanceof UserInterface) {
                throw new \RuntimeException('processAutoLoginToken() must return a UserInterface implementation.');
            }

            // **
            // Reconstruct the old, already authenticated, token composed of
            // all of a token's components including: user, raw token, payload
            // and provider key.
            //
            // The remember-me services here are not designed to refresh the
            // user's token (that's what the RefreshTokenListener will do, if
            // authentication is successful), but to resolve a user's identity
            // and return it in a token that can be passed along to the
            // appropriate authentication provider. [SWQ]
            $oldToken = new JsonWebToken($user, $rawToken, $this->providerKey);
            $oldToken->setPayload($payload);
            return $oldToken;
        }
        catch (InvalidTokenException $ex) {
            if (null !== $this->logger) {
                $this->logger->info('Token not found.');
            }
        }
        catch (UsernameNotFoundException $ex) {
            if (null !== $this->logger) {
                $this->logger->info('User for token refresh not found.');
            }
        }
        catch (UnsupportedUserException $ex) {
            if (null !== $this->logger) {
                $this->logger->warning('User class for token refresh not supported.');
            }
        }
        catch (AuthenticationException $ex) {
            if (null !== $this->logger) {
                $this->logger->debug('Token refresh authentication failed.', array('exception' => $ex));
            }
        }
        // TODO: Traditional remember-me services cancel the remember-me cookie, I don't believe there is a corrolary here...
    }

    /**
     * Decodes the content of a JSON Web Token (JWT) and returns the payload.
     *
     * If the decode fails, either because the token is invalid or expired,
     * then an appropriate exception will be raised.
     *
     * @param string $rawToken The raw token to decode.
     * @throws InvalidTokenException If the token is invalid.
     * @throws ExpiredTokenException If the token has expired.
     * @return array the decoded payload.
     */
    protected function decodePayload($rawToken)
    {
        try {
            $payload = $this->jsonWebTokenManager->decode($rawToken);
            if (!$payload) {
                throw new InvalidTokenException('Invalid JWT Token');
            }
            return $payload;
        }
        catch (JwtDecodeFailureException $ex) {
            if (JwtDecodeFailureException::EXPIRED_TOKEN === $ex->getReason()) {
                throw new ExpiredTokenException();
            }
            throw new InvalidTokenException('Invalid JWT Token', 0, $ex);
        }
    }

    /**
     * Returns the configured <code>$tokenExtractor</code>.
     *
     * @return \Rhapsody\SecurityBundle\Security\Jwt\TokenExtractor\TokenExtractorInterface
     */
    protected function getTokenExtractor()
    {
        return $this->tokenExtractor;
    }

    /**
     *
     */
    final protected function getUserProvider($class)
    {
        // foreach ($this->userProviders as $provider) {
        //     if ($provider->supportsClass($class)) {
        //         return $provider;
        //     }
        // }
        // throw new UnsupportedUserException(sprintf('There is no user provider that supports class "%s".', $class));
        throw new \RuntimeException('Multiple user providers not yet supported for JWT remember-me services; this is still in draft.');
    }

    /**
     * Implementation for RememberMeServicesInterface. Deletes the cookie when
     * an attempted authentication fails.
     *
     * @param Request $request
     */
    final public function loginFail(Request $request)
    {
        $this->onLoginFail($request);

        // TODO: Fire an event indicating that the authentication failed?
        // $event = new AuthenticationFailureEvent($exception, new JwtAuthenticationFailureResponse());
        // $this->eventDispatcher(RhapsodySecurityEvents::JWT_REFRESH_FAILED, $event);
    }

    /**
     * Implementation for RememberMeServicesInterface. This is called when an
     * authentication is successful.
     *
     * @param Request        $request
     * @param Response       $response
     * @param TokenInterface $token    The token that resulted in a successful authentication
     */
    final public function loginSuccess(Request $request, Response $response, TokenInterface $token)
    {
//         // Make sure any old remember-me cookies are cancelled
//         $this->cancelCookie($request);
//
        if (!$token->getUser() instanceof UserInterface) {
            if (null !== $this->logger) {
                $this->logger->debug('JWT remember-me services ignore tokens that do not contain a valid UserInterface implementation.');
            }
            return;
        }

//         if (!$this->isRememberMeRequested($request)) {
//             if (null !== $this->logger) {
//                 $this->logger->debug('Remember-me was not requested.');
//             }
//
//             return;
//         }
//
//         if (null !== $this->logger) {
//             $this->logger->debug('Remember-me was requested; setting cookie.');
//         }
//
//         // Remove attribute from request that sets a NULL cookie.
//         // It was set by $this->cancelCookie()
//         // (cancelCookie does other things too for some RememberMeServices
//         // so we should still call it at the start of this method)
//         $request->attributes->remove(self::COOKIE_ATTR_NAME);
//
        $this->onLoginSuccess($request, $response, $token);
    }

    /**
     * Implementation for LogoutHandlerInterface. Deletes the cookie.
     *
     * @param Request        $request
     * @param Response       $response
     * @param TokenInterface $token
     */
    public function logout(Request $request, Response $response, TokenInterface $token)
    {
        // TODO: Something...?
    }

    /**
     * @param Request $request
     */
    protected function onLoginFail(Request $request)
    {
        // Empty. Concrete JWT remember me services must implements.
    }

    /**
     * This is called after a user has been logged in successfully, and has
     * requested remember-me capabilities. The implementation usually sets a
     * cookie and possibly stores a persistent record of it.
     *
     * @param Request        $request
     * @param Response       $response
     * @param TokenInterface $token
     */
    abstract protected function onLoginSuccess(Request $request, Response $response, TokenInterface $token);

    /**
     *
     * @param unknown $payload
     * @param Request $request
     * @throws \Symfony\Component\Security\Core\Exception\AuthenticationException
     * @throws \RuntimeException
     * @return \Symfony\Component\Security\Core\User\UserInterface
     */
    abstract protected function processAutoLoginToken($payload, Request $request);

    /**
     * Resolves the raw JSON Web Token (JWT) from the <code>$request</code> and
     * returns it.
     *
     * This method uses the <code>$tokenExtractor</code> to resolve the token
     * from the request's headers, cookies, or query parameter.
     *
     * @param Request $request The request that carries the JWT.
     * @return TokenInterface the resolved JWT token.
     */
    private function resolveToken(Request $request)
    {
        $tokenExtractor = $this->getTokenExtractor();
        if (!$tokenExtractor instanceof TokenExtractorInterface) {
            throw new \RuntimeException(sprintf('Method "%s::getTokenExtractor()" must return an instance of "%s".', __CLASS__, TokenExtractorInterface::class));
        }

        $rawToken = $this->tokenExtractor->extract($request);
        if (false === $rawToken) {
            throw new MissingTokenException();
        }
        return new JsonWebToken(null, $rawToken, $this->providerKey);
    }
}