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
namespace Rhapsody\SecurityBundle\Security\Http\Firewall;

use Psr\Log\LoggerInterface;
use Rhapsody\SecurityBundle\RhapsodySecurityEvents;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtRefreshedEvent;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\RememberMe\RememberMeServicesInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebTokenInterface;

/**
 * An alternative to the remember me firewall for token refresh.
 *
 * @author sean.quinn
 */
final class RefreshTokenListener implements ListenerInterface
{

    private $authenticationManager;

    /**
     *
     * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface
     */
    private $eventDispatcher;

    /**
     * @var \Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface
     */
    private $failureHandler;

    /**
     *
     * @var \Symfony\Component\Security\Http\HttpUtils
     */
    private $httpUtils;

    /**
     * @var \Psr\Log\LoggerInterface
     */
    private $logger;

    /**
     *
     * @var \Symfony\Component\Security\Http\RememberMe\RememberMeServicesInterface
     */
    private $rememberMeServices;

    /**
     *
     * @var \Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface
     */
    private $successHandler;

    private $tokenStorage;

    /**
     *
     * @param RememberMeServicesInterface $rememberMeServices
     * @param AuthenticationManagerInterface $authenticationManager
     * @param HttpUtils $httpUtils
     * @param string $providerKey
     * @param AuthenticationSuccessHandlerInterface $successHandler
     * @param AuthenticationFailureHandlerInterface $failureHandler
     * @param array $options
     * @param LoggerInterface $logger
     * @param EventDispatcherInterface $dispatcher
     */
    public function __construct(
        RememberMeServicesInterface $rememberMeServices,
        AuthenticationManagerInterface $authenticationManager,
        HttpUtils $httpUtils,
        $providerKey,
        AuthenticationSuccessHandlerInterface $successHandler,
        AuthenticationFailureHandlerInterface $failureHandler,
        array $options = array(),
        LoggerInterface $logger = null,
        EventDispatcherInterface $eventDispatcher = null)
    {
        $this->rememberMeServices = $rememberMeServices;
        $this->authenticationManager = $authenticationManager;
        $this->httpUtils = $httpUtils;
        $this->providerKey = $providerKey;
        $this->successHandler = $successHandler;
        $this->failureHandler = $failureHandler;
        $this->options = array_merge(array(
            'path' => '/token_refresh',
            // 'always_use_default_target_path' => false,
            // 'default_target_path' => '/',
            // 'target_path_parameter' => '_target_path',
            // 'use_referer' => false,
            // 'failure_path' => null,
            // 'failure_forward' => false,
            // 'require_previous_session' => true,
        ), $options);
        $this->logger = $logger;
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * Handles the refresh of a JSON Web Token (JWT) according to the configured
     * <code>$rememberMeServices</code>.
     *
     * The remember me services will return a JWT that represents the current
     * user's session. This token is then passed into an authentication manager
     * which will issue a new, valid, JWT as well as dispatch an event
     * indicating that the JWT was refreshed before passing the new token to
     * a success handler.
     *
     * If at any point there is a failure, the listener will react accordingly,
     * often raising an exception up the stack.
     *
     * @param GetResponseEvent $event A GetResponseEvent instance.
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();
        if (!$this->handleRequest($request)) {
            return;
        }

        if (null === $token = $this->rememberMeServices->autoLogin($request)) {
            return;
        }

        try {
            $token = $this->authenticationManager->authenticate($token); // <-- this should generate a new JWT complete with events through the JwtAuthenticationProvider
            if (!$token instanceof TokenInterface) {
                throw new \RuntimeException(sprintf('%s::authentication() must return either return a Response, an implementation of TokenInterface, or null.', get_class($this->authenticationManager)));
            }
            $response = $this->onSuccess($request, $token);
            if (null !== $this->eventDispatcher) {
                $refreshEvent = new JwtRefreshedEvent(array(
                    'token' => $token->getCredentials()
                ), $token->getUser(), $response);
                $this->eventDispatcher->dispatch(RhapsodySecurityEvents::JWT_REFRESHED, $refreshEvent);
            }
        }
        catch (AuthenticationException $ex) {
            $response = $this->onFailure($request, $ex);
        }

        $event->setResponse($response);
    }

    /**
     * Whether this request should be handled or not.
     *
     * The refresh token listener only processes requests to a specific path,
     * specified in the firewall's configuration.
     *
     * @param Request $request The request.
     * @return bool <code>true</code> if this request should be processed for
     *     handling a JSON web token refresh; otherwise <code>false</code>.
     */
    protected function handleRequest(Request $request)
    {
        return $this->httpUtils->checkRequestPath($request, $this->options['path']);
    }

    /**
     * Reacts to authentication failure.
     *
     * @param Request $request The request.
     * @param AuthenticationException $failed The authentication exception.
     * @return \Symfony\Component\HttpFoundation\Response
     * @throws \RuntimeException if the response is not an instance of the
     *     <code>Response</code>
     */
    private function onFailure(Request $request, AuthenticationException $failed)
    {
        if (null !== $this->logger) {
            $this->logger->info('Refresh token request failed.', array('exception' => $failed));
        }
        /*
         $token = $this->tokenStorage->getToken();
         if ($token instanceof UsernamePasswordToken && $this->providerKey === $token->getProviderKey()) {
         $this->tokenStorage->setToken(null);
         }
         */
        $response = $this->failureHandler->onAuthenticationFailure($request, $failed);
        if (!$response instanceof Response) {
            throw new \RuntimeException('Authentication Failure Handler did not return a Response.');
        }

        if (null !== $this->rememberMeServices) {
            $this->rememberMeServices->loginFail($request);
        }
        return $response;
    }

    private function onSuccess(Request $request, TokenInterface $token)
    {
        $response = $this->successHandler->onAuthenticationSuccess($request, $token);

        if (!$response instanceof Response) {
            throw new \RuntimeException('Authentication Success Handler did not return a Response.');
        }

        if (null !== $this->rememberMeServices) {
            $this->rememberMeServices->loginSuccess($request, $response, $token);
        }
        return $response;
    }

}