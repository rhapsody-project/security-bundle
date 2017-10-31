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
use Rhapsody\SecurityBundle\Security\Http\Authentication\JwtAuthenticationFailureHandler;
use Rhapsody\SecurityBundle\Security\Jwt\Event\AuthenticationFailureEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Response\JwtAuthenticationFailureResponse;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 *
 */
class JwtAuthenticationFailureHandlerTest extends TestCase
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

    public function testOnAuthenticationFailure()
    {
        $eventDispatcher = $this->getEventDispatcher();
        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with(RhapsodySecurityEvents::JWT_AUTHENTICATION_FAILURE, $this->isInstanceOf(AuthenticationFailureEvent::class));

        $handler = new JwtAuthenticationFailureHandler($eventDispatcher);
        $actual = $handler->onAuthenticationFailure($this->createMock(Request::class), $this->createMock(AuthenticationException::class));
        $this->assertInstanceOf(JwtAuthenticationFailureResponse::class, $actual);
    }

}
