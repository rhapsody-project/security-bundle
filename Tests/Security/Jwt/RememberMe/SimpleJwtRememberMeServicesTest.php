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
namespace Rhapsody\SecurityBundle\Tests\Security\Jwt\RememberMe;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebToken;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebTokenInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\InvalidPayloadException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\JwtDecodeFailureException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\MissingTokenException;
use Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface;
use Rhapsody\SecurityBundle\Security\Jwt\RememberMe\SimpleJwtRememberMeServices;
use Rhapsody\SecurityBundle\Security\Jwt\TokenExtractor\TokenExtractorInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 *
 * @author sean.quinn
 */
class SimpleJwtRememberMeServicesTest extends TestCase
{

    private function getJsonWebTokenManagerMock($expected = null)
    {
        $jwtManager = $this->getMockBuilder(JsonWebTokenManagerInterface::class)
            ->getMock();

        // **
        // We're baking in a couple of mocks here to make the rest of the test
        // cases less verbose; if we specify a non null value for the $expected
        // result of a payload decode, then we should also expect that one of
        // two things will happen when the code attempts to resolve the identity
        // of the user from the payload:
        //
        //   1. The identity will be returned.
        //
        //      or...
        //
        //   2. An invalid payload exception will be raised.
        //
        // These are the ONLY two outcomes for this method call.
        //
        // Using this method to create a viable mock is pretty straight forward,
        // just pass an array with a user's identity (e.g. 'jameskirk') mapped
        // to the 'username' key. [SWQ]
        if (null !== $expected) {
            $jwtManager->expects($this->once())
                ->method('decode')
                ->with('jwt_token')
                ->willReturn($expected);
            if (isset($expected['username'])) {
                $jwtManager->expects($this->once())
                    ->method('getUserIdentityFromPayload')
                    ->with($expected)
                    ->willReturn($expected['username']);
            }
            else {
                $jwtManager->expects($this->once())
                    ->method('getUserIdentityFromPayload')
                    ->with($expected)
                    ->willThrowException(new InvalidPayloadException('username'));
            }
        }
        return $jwtManager;
    }

    private function getLoggerMock(array $expectedMessages = array())
    {
        $logger = $this->getMockBuilder(LoggerInterface::class)
            ->getMock();
        if (!empty($expectedMessages)) {
            foreach ($expectedMessages as $level => $messages) {
                $logger->expects($this->exactly(count($messages)))
                    ->method($level)
                    ->withConsecutive(...$messages);
            }
        }
        return $logger;
    }

    private function getTokenExtractorMock($expected = null)
    {
        $tokenExtractor = $this->getMockBuilder(TokenExtractorInterface::class)
            ->getMock();
        if (null !== $expected) {
            $tokenExtractor->expects($this->once())
                ->method('extract')
                ->with($this->isInstanceOf(Request::class))
                ->willReturn($expected);
        }
        return $tokenExtractor;
    }

    private function getUserProviderMock()
    {
        $userProvider = $this->getMockBuilder(UserProviderInterface::class)
            ->getMock();
        return $userProvider;
    }

    public function testAutoLogin()
    {
        $user = $this->createMock(UserInterface::class);

        $tokenExtractor = $this->getTokenExtractorMock('jwt_token');
        $jwtManager = $this->getJsonWebTokenManagerMock(array('username' => 'jameskirk'));
        $logger = $this->getLoggerMock();
        $userProvider = $this->getUserProviderMock();
        $userProvider->expects($this->once())
            ->method('loadUserByUsername')
            ->with('jameskirk')
            ->willReturn($user);

        $rememberMeServices = new SimpleJwtRememberMeServices(
                $userProvider,
                $tokenExtractor,
                $jwtManager,
                'foo',
                array(),
                $logger);

        $request = new Request();
        $actual = $rememberMeServices->autoLogin($request);
        $this->assertNotNull($actual);
        $this->assertInstanceOf(JsonWebTokenInterface::class, $actual);
        $this->assertSame($user, $actual->getUser());
        $this->assertSame('jwt_token', $actual->getCredentials());
        $this->assertSame(array('username' => 'jameskirk'), $actual->getPayload());
        $this->assertSame('foo', $actual->getProviderKey());
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage The UserProviderInterface implementation must return an instance of UserInterface, but returned "stdClass".
     */
    public function testAutoLoginUserDoesNotImplementCorrectInterface()
    {
        $tokenExtractor = $this->getTokenExtractorMock('jwt_token');
        $jwtManager = $this->getJsonWebTokenManagerMock(array('username' => 'jameskirk'));
        $logger = $this->getLoggerMock();
        $userProvider = $this->getUserProviderMock();
        $userProvider->expects($this->once())
            ->method('loadUserByUsername')
            ->with('jameskirk')
            ->willReturn(new \stdClass());

        $rememberMeServices = new SimpleJwtRememberMeServices(
                $userProvider,
                $tokenExtractor,
                $jwtManager,
                'foo',
                array(),
                $logger);

        $request = new Request();
        $rememberMeServices->autoLogin($request);
    }

    public function testAutoLoginUsernameNotFoundExceptionRaised()
    {
        $tokenExtractor = $this->getTokenExtractorMock('jwt_token');
        $jwtManager = $this->getJsonWebTokenManagerMock(array('username' => 'jameskirk'));
        $userProvider = $this->getUserProviderMock();
        $userProvider->expects($this->once())
            ->method('loadUserByUsername')
            ->with('jameskirk')
            ->willThrowException(new UsernameNotFoundException());

        // ** Mock the logger with expected logging...
        $logger = $this->getLoggerMock(array(
            'info' => [
                array('User for token refresh not found.')
            ]
        ));

        $rememberMeServices = new SimpleJwtRememberMeServices(
                $userProvider,
                $tokenExtractor,
                $jwtManager,
                'foo',
                array(),
                $logger);

        $request = new Request();
        $rememberMeServices->autoLogin($request);
    }

    public function testAutoLoginWhenPayloadDecodeFailsDueToExpiredToken()
    {
        $tokenExtractor = $this->getTokenExtractorMock('jwt_token');
        $jwtManager = $this->getJsonWebTokenManagerMock();
        $jwtManager->expects($this->once())
            ->method('decode')
            ->with('jwt_token')
            ->willThrowException(new JwtDecodeFailureException(JwtDecodeFailureException::EXPIRED_TOKEN));
        $userProvider = $this->getUserProviderMock();

        // ** Mock the logger with expected logging...
        $logger = $this->getLoggerMock(array(
            'debug' => [
                array('Token refresh authentication failed.', $this->anything())
            ]
        ));

        $rememberMeServices = new SimpleJwtRememberMeServices(
                $userProvider,
                $tokenExtractor,
                $jwtManager,
                'foo',
                array(),
                $logger);

        $request = new Request();
        $rememberMeServices->autoLogin($request);
    }

    public function testAutoLoginWhenPayloadDecodeFailsDueToInvalidToken()
    {
        $tokenExtractor = $this->getTokenExtractorMock('jwt_token');
        $jwtManager = $this->getJsonWebTokenManagerMock();
        $jwtManager->expects($this->once())
            ->method('decode')
            ->with('jwt_token')
            ->willThrowException(new JwtDecodeFailureException(JwtDecodeFailureException::INVALID_TOKEN));
        $userProvider = $this->getUserProviderMock();

        // ** Mock the logger with expected logging...
        $logger = $this->getLoggerMock(array(
            'info' => [
                array('Token not found.')
            ]
        ));

        $rememberMeServices = new SimpleJwtRememberMeServices(
                $userProvider,
                $tokenExtractor,
                $jwtManager,
                'foo',
                array(),
                $logger);

        $request = new Request();
        $rememberMeServices->autoLogin($request);
    }

    public function testAutoLoginWhenPayloadDecodesToNull()
    {
        $tokenExtractor = $this->getTokenExtractorMock('jwt_token');
        $jwtManager = $this->getJsonWebTokenManagerMock();
        $jwtManager->expects($this->once())
            ->method('decode')
            ->with('jwt_token')
            ->willReturn(null);
        $userProvider = $this->getUserProviderMock();

        // ** Mock the logger with expected logging...
        $logger = $this->getLoggerMock(array(
            'info' => [
                array('Token not found.')
            ]
        ));

        $rememberMeServices = new SimpleJwtRememberMeServices(
                $userProvider,
                $tokenExtractor,
                $jwtManager,
                'foo',
                array(),
                $logger);

        $request = new Request();
        $rememberMeServices->autoLogin($request);
    }

    /**
     * @expectedException \Rhapsody\SecurityBundle\Security\Jwt\Exception\MissingTokenException
     */
    public function testAutoLoginWithNoJwtToken()
    {
        $tokenExtractor = $this->getTokenExtractorMock(false);
        $jwtManager = $this->getJsonWebTokenManagerMock();
        $logger = $this->getLoggerMock();
        $userProvider = $this->getUserProviderMock();

        $rememberMeServices = new SimpleJwtRememberMeServices(
                $userProvider,
                $tokenExtractor,
                $jwtManager,
                'foo',
                array(),
                $logger);

        $request = new Request();
        $rememberMeServices->autoLogin($request);
    }

    public function testLoginFail()
    {
        $tokenExtractor = $this->getTokenExtractorMock();
        $jwtManager = $this->getJsonWebTokenManagerMock();
        $logger = $this->getLoggerMock();
        $userProvider = $this->getUserProviderMock();

        $rememberMeServices = new SimpleJwtRememberMeServices(
                $userProvider,
                $tokenExtractor,
                $jwtManager,
                'foo',
                array(),
                $logger);

        $request = new Request();
        $actual = $rememberMeServices->loginFail($request);
    }

    public function testLoginSuccess()
    {
        $user = $this->createMock(UserInterface::class);

        $tokenExtractor = $this->getTokenExtractorMock();
        $jwtManager = $this->getJsonWebTokenManagerMock();
        $logger = $this->getLoggerMock();
        $userProvider = $this->getUserProviderMock();

        $rememberMeServices = new SimpleJwtRememberMeServices(
                $userProvider,
                $tokenExtractor,
                $jwtManager,
                'foo',
                array(),
                $logger);

        $request = new Request();
        $response = new Response();
        $token = new JsonWebToken($user, 'jwt_token', 'foo');
        $rememberMeServices->loginSuccess($request, $response, $token);

        // $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);
        // $cookie = $cookies['myfoodomain.foo']['/foo/path']['foo'];
        // $this->assertFalse($cookie->isCleared());
        // $this->assertTrue($cookie->isSecure());
        // $this->assertTrue($cookie->isHttpOnly());
        // $this->assertTrue($cookie->getExpiresTime() > time() + 3590 && $cookie->getExpiresTime() < time() + 3610);
        // $this->assertEquals('myfoodomain.foo', $cookie->getDomain());
        // $this->assertEquals('/foo/path', $cookie->getPath());
    }

    public function testLoginSuccessForTokenWithInvalidUser()
    {
        $tokenExtractor = $this->getTokenExtractorMock();
        $jwtManager = $this->getJsonWebTokenManagerMock();
        $userProvider = $this->getUserProviderMock();

        // ** Mock the logger.
        $logger = $this->getLoggerMock(array(
            'debug' => [
                array('JWT remember-me services ignore tokens that do not contain a valid UserInterface implementation.')
            ]
        ));

        $rememberMeServices = new SimpleJwtRememberMeServices(
                $userProvider,
                $tokenExtractor,
                $jwtManager,
                'foo',
                array(),
                $logger);

        $request = new Request();
        $response = new Response();
        $token = $this->createMock(TokenInterface::class);
        $token->expects($this->once())
            ->method('getUser')
            ->willReturn(new \stdClass);
        $rememberMeServices->loginSuccess($request, $response, $token);

        // $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);
        // $cookie = $cookies['myfoodomain.foo']['/foo/path']['foo'];
        // $this->assertFalse($cookie->isCleared());
        // $this->assertTrue($cookie->isSecure());
        // $this->assertTrue($cookie->isHttpOnly());
        // $this->assertTrue($cookie->getExpiresTime() > time() + 3590 && $cookie->getExpiresTime() < time() + 3610);
        // $this->assertEquals('myfoodomain.foo', $cookie->getDomain());
        // $this->assertEquals('/foo/path', $cookie->getPath());
    }

    public function testLoginSuccessForTokenWithNullUser()
    {
        $tokenExtractor = $this->getTokenExtractorMock();
        $jwtManager = $this->getJsonWebTokenManagerMock();
        $userProvider = $this->getUserProviderMock();

        // ** Mock the logger.
        $logger = $this->getLoggerMock(array(
            'debug' => [
                array('JWT remember-me services ignore tokens that do not contain a valid UserInterface implementation.')
            ]
        ));

        $rememberMeServices = new SimpleJwtRememberMeServices(
                $userProvider,
                $tokenExtractor,
                $jwtManager,
                'foo',
                array(),
                $logger);

        $request = new Request();
        $response = new Response();
        $token = new JsonWebToken(null, 'jwt_token', 'foo');
        $rememberMeServices->loginSuccess($request, $response, $token);

        // $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);
        // $cookie = $cookies['myfoodomain.foo']['/foo/path']['foo'];
        // $this->assertFalse($cookie->isCleared());
        // $this->assertTrue($cookie->isSecure());
        // $this->assertTrue($cookie->isHttpOnly());
        // $this->assertTrue($cookie->getExpiresTime() > time() + 3590 && $cookie->getExpiresTime() < time() + 3610);
        // $this->assertEquals('myfoodomain.foo', $cookie->getDomain());
        // $this->assertEquals('/foo/path', $cookie->getPath());
    }

    public function testLogout()
    {
        $user = $this->createMock(UserInterface::class);

        $tokenExtractor = $this->getTokenExtractorMock();
        $jwtManager = $this->getJsonWebTokenManagerMock();
        $logger = $this->getLoggerMock();
        $userProvider = $this->getUserProviderMock();

        $rememberMeServices = new SimpleJwtRememberMeServices(
                $userProvider,
                $tokenExtractor,
                $jwtManager,
                'foo',
                array(),
                $logger);

        $request = new Request();
        $response = new Response();
        $token = new JsonWebToken($user, 'jwt_token', 'foo');
        $rememberMeServices->logout($request, $response, $token);

        // $cookie = $request->attributes->get(SimpleJwtRememberMeServices::COOKIE_ATTR_NAME);
        // $this->assertTrue($cookie->isCleared());
        // $this->assertEquals('/foo', $cookie->getPath());
        // $this->assertEquals('foodomain.foo', $cookie->getDomain());
        // $this->assertTrue($cookie->isSecure());
        // $this->assertFalse($cookie->isHttpOnly());
    }

    public function testResolveToken()
    {
        $tokenExtractor = $this->getTokenExtractorMock('jwt_token');
        $jwtManager = $this->getJsonWebTokenManagerMock();
        $logger = $this->getLoggerMock();
        $userProvider = $this->getUserProviderMock();

        $rememberMeServices = new SimpleJwtRememberMeServices(
                $userProvider,
                $tokenExtractor,
                $jwtManager,
                'foo',
                array(),
                $logger);

        $request = new Request();

        $m = new \ReflectionMethod($rememberMeServices, 'resolveToken');
        $m->setAccessible(true);
        $actual = $m->invoke($rememberMeServices, $request);
        $this->assertNotNull($actual);
        $this->assertInstanceOf(JsonWebTokenInterface::class, $actual);
        $this->assertSame('jwt_token', $actual->getCredentials());
        $this->assertSame('foo', $actual->getProviderKey());
    }

    /**
     * @expectedException \Rhapsody\SecurityBundle\Security\Jwt\Exception\MissingTokenException
     */
    public function testResolveTokenOnRequestWithoutJWT()
    {
        $tokenExtractor = $this->getTokenExtractorMock(false);
        $jwtManager = $this->getJsonWebTokenManagerMock();
        $logger = $this->getLoggerMock();
        $userProvider = $this->getUserProviderMock();

        $rememberMeServices = new SimpleJwtRememberMeServices(
                $userProvider,
                $tokenExtractor,
                $jwtManager,
                'foo',
                array(),
                $logger);

        $request = new Request();

        $m = new \ReflectionMethod($rememberMeServices, 'resolveToken');
        $m->setAccessible(true);
        $m->invoke($rememberMeServices, $request);
    }


    /**
     * This tests an almost impossible scenario with the way the code is
     * structured currently: the resolution of a token extractor that does not
     * implement the the <code>TokenExtractorInterface</code>.
     *
     * To do this, we mock the <code>getTokenExtractor</code> method and invoke
     * the <code>resolveToken</code> method.
     *
     * @expectedException \RuntimeException
     */
    public function testResolveTokenWithInvalidTokenExtractor()
    {
        $rememberMeServices = $this->getMockBuilder(SimpleJwtRememberMeServices::class)
            ->disableOriginalConstructor()
            ->setMethods(['getTokenExtractor'])
            ->getMock();

        $rememberMeServices->expects($this->once())
            ->method('getTokenExtractor')
            ->willReturn(null);

        $request = new Request();

        $m = new \ReflectionMethod($rememberMeServices, 'resolveToken');
        $m->setAccessible(true);
        $m->invoke($rememberMeServices, $request);
    }

}
