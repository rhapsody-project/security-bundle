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
namespace Rhapsody\SecurityBundle\Tests\Security\Http\Authentication;

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\RhapsodySecurityEvents;
use Rhapsody\SecurityBundle\Security\Http\Authentication\JwtAuthenticationSuccessHandler;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebToken;
use Rhapsody\SecurityBundle\Security\Jwt\Event\AuthenticationSuccessEvent;
use Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Response\JwtAuthenticationSuccessResponse;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 *
 */
class JwtAuthenticationSuccessHandlerTest extends TestCase
{

    /**
     * Returns a mock <code>EventDispatcherInterface</code>.
     *
     * @return \PHPUnit_Framework_MockObject_MockObject a mock event dispatcher.
     */
    private function getEventDispatcher()
    {
        $eventDispatcher = $this->getMockBuilder(EventDispatcherInterface::class)
            ->getMock();
        return $eventDispatcher;
    }

    /**
     * Returns a mock <code>JsonWebTokenManagerInterface</code>.
     *
     * @return \PHPUnit_Framework_MockObject_MockObject a mock event dispatcher.
     */
    private function getJsonWebTokenManager()
    {
        $jwtManager = $this->getMockBuilder(JsonWebTokenManagerInterface::class)
           ->getMock();
        return $jwtManager;
    }

    public function testOnAuthenticationSuccess()
    {
        $jwtManager = $this->getJsonWebTokenManager();
        $eventDispatcher = $this->getEventDispatcher();

        $user = $this->createMock(UserInterface::class);
        $token = new JsonWebToken($user, 'token');

        $jwtManager->expects($this->once())
            ->method('createToken')
            ->with($user)
            ->willReturn($token);

        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with(RhapsodySecurityEvents::JWT_AUTHENTICATION_SUCCESS, $this->isInstanceOf(AuthenticationSuccessEvent::class));

        $handler = new JwtAuthenticationSuccessHandler($jwtManager, $eventDispatcher);
        $actual = $handler->onAuthenticationSuccess($this->createMock(Request::class), $token);
        $this->assertNotNull($actual);
        $this->assertInstanceOf(JwtAuthenticationSuccessResponse::class, $actual);
        $this->assertSame($token->getRawToken(), $actual->getRawToken());
    }

}
