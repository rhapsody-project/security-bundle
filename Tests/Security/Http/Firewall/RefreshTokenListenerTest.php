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
namespace Rhapsody\SecurityBundle\Tests\Security\Http\Firewall;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Rhapsody\SecurityBundle\Security\Http\Firewall\RefreshTokenListener;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebTokenInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Response\JwtAuthenticationFailureResponse;
use Rhapsody\SecurityBundle\Security\Jwt\Response\JwtAuthenticationSuccessResponse;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\RememberMe\RememberMeServicesInterface;

class RefreshTokenListenerTest extends TestCase
{

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject
     */
    private function getAuthenticationFailureHandlerMock()
    {
        $authenticationFailureHandler = $this->getMockBuilder(AuthenticationFailureHandlerInterface::class)
            ->getMock();
        return $authenticationFailureHandler;
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject
     */
    private function getAuthenticationManagerMock()
    {
        $authenticationManager = $this->getMockBuilder(AuthenticationManagerInterface::class)->getMock();
        return $authenticationManager;
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject
     */
    private function getAuthenticationSuccessHandlerMock()
    {
        $authenticationSuccessHandler = $this->getMockBuilder(AuthenticationSuccessHandlerInterface::class)
            ->getMock();
        return $authenticationSuccessHandler;
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject
     */
    private function getEventDispatcherMock()
    {
        $eventDispatcher = $this->getMockBuilder(EventDispatcherInterface::class)->getMock();
        return $eventDispatcher;
    }

    /**
     *
     * @return \PHPUnit_Framework_MockObject_MockObject
     */
    private function getGetResponseEventMock($request = null)
    {
        $event = $this->getMockBuilder(GetResponseEvent::class)
            ->disableOriginalConstructor()
            ->getMock();

        if ($request) {
            $event->expects($this->once())
                ->method('getRequest')
                ->willReturn($request);
        }
        return $event;
    }

    /**
     * @param string $checkRequestPath
     * @return PHPUnit_Framework_MockObject_MockObject
     */
    private function getHttpUtilsMock($checkRequestPath = true)
    {
        $httpUtils = $this->getMockBuilder(HttpUtils::class)->getMock();
        $httpUtils->expects($this->any())
            ->method('checkRequestPath')
            ->willReturn($checkRequestPath);
        return $httpUtils;
    }

    /**
     * @return PHPUnit_Framework_MockObject_MockObject
     */
    private function getLoggerMock()
    {
        $logger = $this->getMockBuilder(LoggerInterface::class)->getMock();
        return $logger;
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject
     */
    private function getRememberMeServicesMock()
    {
        $rememberMeServices = $this->getMockBuilder(RememberMeServicesInterface::class)->getMock();
        return $rememberMeServices;
    }

    private function createRequest($uri, $method, array $headers = array())
    {
        return Request::create('/token_refresh', 'POST', array(), array(), array(), $headers, null);
    }

    public function testHandle()
    {
        $rememberMeServices = $this->getRememberMeServicesMock();
        $authenticationManager = $this->getAuthenticationManagerMock();
        $httpUtils = $this->getHttpUtilsMock();
        $successHandler = $this->getAuthenticationSuccessHandlerMock();
        $failureHandler = $this->getAuthenticationFailureHandlerMock();
        $options = array();
        $logger = $this->getLoggerMock();
        $eventDispatcher = $this->getEventDispatcherMock();

        $listener = new RefreshTokenListener(
                $rememberMeServices,
                $authenticationManager,
                $httpUtils,
                'foo',
                $successHandler,
                $failureHandler,
                $options,
                $logger,
                $eventDispatcher);

        $request = $this->createRequest('/token_refresh', 'POST', array(
            'HTTP_AUTHORIZATION' => 'Bearer encodedJwt'
        ));
        $event = $this->getGetResponseEventMock($request);
        $listener->handle($event);
    }

    public function testHandleIgnoresUnconfiguredPath()
    {
        $rememberMeServices = $this->getRememberMeServicesMock();
        $authenticationManager = $this->getAuthenticationManagerMock();
        $httpUtils = $this->getHttpUtilsMock(false);
        $successHandler = $this->getAuthenticationSuccessHandlerMock();
        $failureHandler = $this->getAuthenticationFailureHandlerMock();
        $options = array();
        $logger = $this->getLoggerMock();
        $eventDispatcher = $this->getEventDispatcherMock();

        $listener = new RefreshTokenListener(
                $rememberMeServices,
                $authenticationManager,
                $httpUtils,
                'foo',
                $successHandler,
                $failureHandler,
                $options,
                $logger,
                $eventDispatcher);

        $request = $this->createRequest('/token_refresh', 'POST', array(
            'HTTP_AUTHORIZATION' => 'Bearer encodedJwt'
        ));
        $event = $this->getGetResponseEventMock($request);
        $listener->handle($event);
    }

    public function testHandleRequest()
    {
        $rememberMeServices = $this->getRememberMeServicesMock();
        $authenticationManager = $this->getAuthenticationManagerMock();
        $httpUtils = $this->getHttpUtilsMock();
        $successHandler = $this->getAuthenticationSuccessHandlerMock();
        $failureHandler = $this->getAuthenticationFailureHandlerMock();
        $options = array();
        $logger = $this->getLoggerMock();
        $eventDispatcher = $this->getEventDispatcherMock();

        $listener = new RefreshTokenListener(
                $rememberMeServices,
                $authenticationManager,
                $httpUtils,
                'foo',
                $successHandler,
                $failureHandler,
                $options,
                $logger,
                $eventDispatcher);

        $m = new \ReflectionMethod($listener, 'handleRequest');
        $m->setAccessible(true);
        $actual = $m->invoke($listener, new Request());
        $this->assertTrue($actual);
    }

    public function testHandleRequestIgnoresUnconfiguredPath()
    {
        $rememberMeServices = $this->getRememberMeServicesMock();
        $authenticationManager = $this->getAuthenticationManagerMock();
        $httpUtils = $this->getHttpUtilsMock(false);
        $successHandler = $this->getAuthenticationSuccessHandlerMock();
        $failureHandler = $this->getAuthenticationFailureHandlerMock();
        $options = array();
        $logger = $this->getLoggerMock();
        $eventDispatcher = $this->getEventDispatcherMock();

        $listener = new RefreshTokenListener(
                $rememberMeServices,
                $authenticationManager,
                $httpUtils,
                'foo',
                $successHandler,
                $failureHandler,
                $options,
                $logger,
                $eventDispatcher);

        $m = new \ReflectionMethod($listener, 'handleRequest');
        $m->setAccessible(true);
        $actual = $m->invoke($listener, new Request());
        $this->assertFalse($actual);
    }

    public function testOnFailure()
    {
        $rememberMeServices = $this->getRememberMeServicesMock();
        $authenticationManager = $this->getAuthenticationManagerMock();
        $eventDispatcher = $this->getEventDispatcherMock();
        $httpUtils = $this->getHttpUtilsMock(false);
        $successHandler = $this->getAuthenticationSuccessHandlerMock();
        $failureHandler = $this->getAuthenticationFailureHandlerMock();
        $options = array();
        $logger = $this->getLoggerMock();
        $eventDispatcher = $this->getEventDispatcherMock();

        $request = $this->createMock(Request::class);
        $failure = $this->createMock(AuthenticationException::class);
        $response = new JwtAuthenticationFailureResponse();

        $failureHandler->expects($this->once())
            ->method('onAuthenticationFailure')
            ->with($request, $failure)
            ->willReturn($response);

        $rememberMeServices->expects($this->once())
            ->method('loginFail')
            ->with($request);

        $listener = new RefreshTokenListener(
                $rememberMeServices,
                $authenticationManager,
                $httpUtils,
                'foo',
                $successHandler,
                $failureHandler,
                $options,
                $logger,
                $eventDispatcher);

        $m = new \ReflectionMethod($listener, 'onFailure');
        $m->setAccessible(true);
        $actual = $m->invoke($listener, $request, $failure);
        $this->assertNotNull($actual);
        $this->assertSame($response, $actual);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Authentication Failure Handler did not return a Response.
     */
    public function testOnFailureWhenFailureHandlerReturnsNonResponseObject()
    {
        $failureHandler = $this->getAuthenticationFailureHandlerMock();
        $logger = $this->getLoggerMock();

        $request = $this->createMock(Request::class);
        $failure = $this->createMock(AuthenticationException::class);

        $failureHandler->expects($this->once())
            ->method('onAuthenticationFailure')
            ->with($request, $failure)
            ->willReturn(new \stdClass());

        $listener = new RefreshTokenListener(
                $this->getRememberMeServicesMock(),
                $this->getAuthenticationManagerMock(),
                $this->getHttpUtilsMock(),
                'foo',
                $this->getAuthenticationSuccessHandlerMock(),
                $failureHandler,
                array(),
                $logger,
                $this->getEventDispatcherMock());

        $m = new \ReflectionMethod($listener, 'onFailure');
        $m->setAccessible(true);
        $m->invoke($listener, $request, $failure);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Authentication Failure Handler did not return a Response.
     */
    public function testOnFailureWhenFailureHandlerReturnsNullResponse()
    {
        $failureHandler = $this->getAuthenticationFailureHandlerMock();
        $logger = $this->getLoggerMock();

        $request = $this->createMock(Request::class);
        $failure = $this->createMock(AuthenticationException::class);

        $failureHandler->expects($this->once())
            ->method('onAuthenticationFailure')
            ->with($request, $failure)
            ->willReturn(new \stdClass());

        $listener = new RefreshTokenListener(
                $this->getRememberMeServicesMock(),
                $this->getAuthenticationManagerMock(),
                $this->getHttpUtilsMock(),
                'foo',
                $this->getAuthenticationSuccessHandlerMock(),
                $failureHandler,
                array(),
                $logger,
                $this->getEventDispatcherMock());

        $m = new \ReflectionMethod($listener, 'onFailure');
        $m->setAccessible(true);
        $m->invoke($listener, $request, $failure);
    }

    public function testOnSuccess()
    {
        $rememberMeServices = $this->getRememberMeServicesMock();
        $successHandler = $this->getAuthenticationSuccessHandlerMock();
        $logger = $this->getLoggerMock();

        $request = $this->createMock(Request::class);
        $token = $this->createMock(JsonWebTokenInterface::class);
        $response = new JwtAuthenticationSuccessResponse($token);

        $successHandler->expects($this->once())
            ->method('onAuthenticationSuccess')
            ->with($this->isInstanceOf(Request::class), $this->isInstanceOf(TokenInterface::class))
            ->willReturn($response);

        $rememberMeServices->expects($this->once())
            ->method('loginSuccess')
            ->with($request, $response, $token);

        $listener = new RefreshTokenListener(
                $rememberMeServices,
                $this->getAuthenticationManagerMock(),
                $this->getHttpUtilsMock(),
                'foo',
                $successHandler,
                $this->getAuthenticationFailureHandlerMock(),
                array(),
                $logger,
                $this->getEventDispatcherMock());

        $m = new \ReflectionMethod($listener, 'onSuccess');
        $m->setAccessible(true);
        $actual = $m->invoke($listener, $request, $token);
        $this->assertNotNull($actual);
        $this->assertSame($response, $actual);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Authentication Success Handler did not return a Response
     */
    public function testOnSuccessWhenSuccessHandlerReturnsNonResponseObject()
    {
        $rememberMeServices = $this->getRememberMeServicesMock();
        $authenticationManager = $this->getAuthenticationManagerMock();
        $eventDispatcher = $this->getEventDispatcherMock();
        $httpUtils = $this->getHttpUtilsMock(false);
        $successHandler = $this->getAuthenticationSuccessHandlerMock();
        $failureHandler = $this->getAuthenticationFailureHandlerMock();
        $options = array();
        $logger = $this->getLoggerMock();
        $eventDispatcher = $this->getEventDispatcherMock();

        $successHandler->expects($this->once())
            ->method('onAuthenticationSuccess')
            ->with($this->isInstanceOf(Request::class), $this->isInstanceOf(TokenInterface::class))
            ->willReturn(new \stdClass());

        $listener = new RefreshTokenListener(
                $rememberMeServices,
                $authenticationManager,
                $httpUtils,
                'foo',
                $successHandler,
                $failureHandler,
                $options,
                $logger,
                $eventDispatcher);

        $request = $this->createMock(Request::class);
        $token = $this->createMock(JsonWebTokenInterface::class);

        $m = new \ReflectionMethod($listener, 'onSuccess');
        $m->setAccessible(true);
        $m->invoke($listener, $request, $token);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Authentication Success Handler did not return a Response
     */
    public function testOnSuccessWhenSuccessHandlerReturnsNullResponse()
    {
        $rememberMeServices = $this->getRememberMeServicesMock();
        $authenticationManager = $this->getAuthenticationManagerMock();
        $eventDispatcher = $this->getEventDispatcherMock();
        $httpUtils = $this->getHttpUtilsMock(false);
        $successHandler = $this->getAuthenticationSuccessHandlerMock();
        $failureHandler = $this->getAuthenticationFailureHandlerMock();
        $options = array();
        $logger = $this->getLoggerMock();
        $eventDispatcher = $this->getEventDispatcherMock();

        $successHandler->expects($this->once())
            ->method('onAuthenticationSuccess')
            ->with($this->isInstanceOf(Request::class), $this->isInstanceOf(TokenInterface::class))
            ->willReturn(null);

        $listener = new RefreshTokenListener(
                $rememberMeServices,
                $authenticationManager,
                $httpUtils,
                'foo',
                $successHandler,
                $failureHandler,
                $options,
                $logger,
                $eventDispatcher);

        $request = $this->createMock(Request::class);
        $token = $this->createMock(JsonWebTokenInterface::class);

        $m = new \ReflectionMethod($listener, 'onSuccess');
        $m->setAccessible(true);
        $m->invoke($listener, $request, $token);
    }

}