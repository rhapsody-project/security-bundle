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
namespace Rhapsody\SecurityBundle\Security\Http\Authentication;

use Rhapsody\SecurityBundle\RhapsodySecurityEvents;
use Rhapsody\SecurityBundle\Security\Jwt\Event\AuthenticationSuccessEvent;
use Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Response\JwtAuthenticationSuccessResponse;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;

/**
 *
 * @author sean.quinn
 */
class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandlerInterface
{
    /**
     * @var \Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface
     */
    protected $jwtManager;

    /**
     * @var EventDispatcherInterface
     */
    protected $eventDispatcher;

    /**
     * @param JWTManager               $jwtManager
     * @param EventDispatcherInterface $dispatcher
     */
    public function __construct(JsonWebTokenManagerInterface $jwtManager, EventDispatcherInterface $eventDispatcher)
    {
        $this->jwtManager = $jwtManager;
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * {@inheritDoc}
     * @see \Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface::onAuthenticationSuccess()
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
        return $this->handleAuthenticationSuccess($token->getUser());
    }

    /**
     *
     * @param UserInterface $user
     * @param unknown $jwt
     * @return \Rhapsody\SecurityBundle\Security\Jwt\Response\JwtAuthenticationSuccessResponse
     */
    public function handleAuthenticationSuccess(UserInterface $user, $jwt = null)
    {
        if (null === $jwt) {
            $jwt = $this->jwtManager->createToken($user);
        }

        $response = new JwtAuthenticationSuccessResponse($jwt);
        $event = new AuthenticationSuccessEvent(['token' => $jwt->getRawToken()], $user, $response);

        $this->eventDispatcher->dispatch(RhapsodySecurityEvents::JWT_AUTHENTICATION_SUCCESS, $event);
        $response->setData($event->getData());
        return $response;
    }
}
