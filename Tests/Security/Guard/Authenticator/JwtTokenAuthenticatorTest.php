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
namespace Rhapsody\SecurityBundle\Tests\Security\Guard\Authenticator;

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\RhapsodySecurityEvents;
use Rhapsody\SecurityBundle\Security\Guard\Authenticator\JwtTokenAuthenticator;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebToken;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtAuthenticatedEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtInvalidEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtNotFoundEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\ExpiredTokenException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\InvalidPayloadException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\InvalidTokenException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\JwtDecodeFailureException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\MissingTokenException;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\UserNotFoundException;
use Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Response\JwtAuthenticationFailureResponse;
use Rhapsody\SecurityBundle\Security\Jwt\TokenExtractor\TokenExtractorInterface;
use Rhapsody\SecurityBundle\Tests\Fixtures\User as UserFixture;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 */
class JwtTokenAuthenticatorTest extends TestCase
{

    /**
     * Return a mock of the <code>EventDispatcherInterface</code>.
     *
     * @return PHPUnit_Framework_MockObject_MockObject
     */
    private function getEventDispatcherMock()
    {
        return $this->getMockBuilder(EventDispatcherInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
    }

    /**
     * Return a mock of the <code>JsonWebTokenManagerInterface</code>.
     *
     * @return \PHPUnit_Framework_MockObject_MockObject
     */
    private function getJsonWebTokenManagerMock($identityClaim = 'username', $userIdentity = null)
    {
        $jwtManager = $this->getMockBuilder(JsonWebTokenManagerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();

        if (null !== $identityClaim) {
            $jwtManager->expects($this->any())
                ->method('getIdentityClaim')
                ->willReturn($identityClaim);
        }

        if (null !== $userIdentity) {
            $jwtManager->expects($this->once())
                ->method('getUserIdentityFromToken')
                ->willReturn($userIdentity);
        }

        return $jwtManager;
    }

    /**
     * Return a mock of a <code>Request</code>.
     *
     * @return PHPUnit_Framework_MockObject_MockObject
     */
    private function getRequestMock()
    {
        return $this->getMockBuilder(Request::class)
            ->disableOriginalConstructor()
            ->getMock();
    }

    private function getTokenExtractorMock($returnValue = null)
    {
        $extractor = $this->getMockBuilder(TokenExtractorInterface::class)
            ->disableOriginalConstructor()
            ->getMock();

        if (null !== $returnValue) {
            $extractor->expects($this->once())
                ->method('extract')
                ->willReturn($returnValue);
        }

        return $extractor;
    }

    private function getUserProviderMock()
    {
        return $this->getMockBuilder(UserProviderInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
    }

    public function testGetCredentials()
    {
        $jwtManager = $this->getJsonWebTokenManagerMock();
        $jwtManager->expects($this->once())
            ->method('decode')
            ->willReturn(['username' => 'jameskirk']);

        $authenticator = new JwtTokenAuthenticator($jwtManager, $this->getEventDispatcherMock(), $this->getTokenExtractorMock('token'));
        $actual = $authenticator->getCredentials($this->getRequestMock());
        $this->assertInstanceOf(JsonWebToken::class, $actual);
    }

    public function testGetCredentialsReturnsNullWithoutToken()
    {
        $authenticator = new JwtTokenAuthenticator($this->getJsonWebTokenManagerMock(), $this->getEventDispatcherMock(), $this->getTokenExtractorMock(false));
        $actual = $authenticator->getCredentials($this->getRequestMock());
        $this->assertNull($actual);
    }

    public function testGetCredentialsWithExpiredTokenThrowsException()
    {
        $jwtManager = $this->getJsonWebTokenManagerMock();
        $jwtManager->expects($this->once())
            ->method('decode')
            ->with(new JsonWebToken(null, 'token'))
            ->will($this->throwException(new JwtDecodeFailureException(JwtDecodeFailureException::EXPIRED_TOKEN, 'Expired Token')));

        try {
            $jwtTokenAuthenticator = new JwtTokenAuthenticator($jwtManager, $this->getEventDispatcherMock(), $this->getTokenExtractorMock('token'));
            $jwtTokenAuthenticator->getCredentials($this->getRequestMock());

            $this->fail(sprintf('Expected exception of type "%s" to be thrown.', ExpiredTokenException::class));
        }
        catch ( ExpiredTokenException $e ) {
            $this->assertSame('Expired Token', $e->getMessageKey());
        }
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testGetCredentialsWithInvalidTokenExtractor()
    {
        $authenticator = $this->getMockBuilder(JwtTokenAuthenticator::class)
            ->disableOriginalConstructor()
            ->setMethods(['getTokenExtractor'])
            ->getMock();

        $authenticator->expects($this->once())
            ->method('getTokenExtractor')
            ->willReturn(null);

        $authenticator->getCredentials($this->getRequestMock());
    }

    public function testGetCredentialsWithInvalidTokenThrowsException()
    {
        try {
            $jwtTokenAuthenticator = new JwtTokenAuthenticator($this->getJsonWebTokenManagerMock(), $this->getEventDispatcherMock(), $this->getTokenExtractorMock('token'));
            $jwtTokenAuthenticator->getCredentials($this->getRequestMock());

            $this->fail(sprintf('Expected exception of type "%s" to be thrown.', InvalidTokenException::class));
        }
        catch (InvalidTokenException $ex) {
            $this->assertSame('Invalid Token', $ex->getMessageKey());
        }
    }

    public function testGetUser()
    {
        $rawToken = 'token';
        $payload = array('username' => 'jameskirk');

        $userStub = new UserFixture('jameskirk', 'password', 'user@gmail.com', ['ROLE_USER']);

        $decodedToken = new JsonWebToken(null, $rawToken);
        $decodedToken->setPayload($payload);

        $jwtManager = $this->getJsonWebTokenManagerMock('username', 'jameskirk');
        $dispatcher = $this->getEventDispatcherMock();
        $userProvider = $this->getUserProviderMock();
        $userProvider->expects($this->once())
            ->method('loadUserByUsername')
            ->with('jameskirk')
            ->willReturn($userStub);

        $authenticator = new JwtTokenAuthenticator($jwtManager, $dispatcher, $this->getTokenExtractorMock());
        $actual = $authenticator->getUser($decodedToken, $userProvider);
        $this->assertSame($userStub, $actual);
    }

    /**
     * @expectedException        \InvalidArgumentException
     * @expectedExceptionMessage must be an instance of "Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebTokenInterface".
     */
    public function testGetUserWithInvalidFirstArg()
    {
        $authenticator = new JwtTokenAuthenticator($this->getJsonWebTokenManagerMock(), $this->getEventDispatcherMock(), $this->getTokenExtractorMock());
        $authenticator->getUser(new \stdClass(), $this->getUserProviderMock());
    }

    public function testGetUserWithInvalidPayloadThrowsException()
    {
        $decodedToken = new JsonWebToken(null, 'rawToken');
        $decodedToken->setPayload([]); // Empty payload

        try {
            $jwtManager = $this->getJsonWebTokenManagerMock('username', null);
            $jwtManager->expects($this->once())
                ->method('getUserIdentityFromToken')
                ->willThrowException(new InvalidPayloadException('username'));

            $dispatcher = $this->getEventDispatcherMock();
            $authenticator = new JwtTokenAuthenticator($jwtManager, $dispatcher, $this->getTokenExtractorMock());
            $authenticator->getUser($decodedToken, $this->getUserProviderMock());

            $this->fail(sprintf('Expected exception of type "%s" to be thrown.', InvalidPayloadException::class));
        }
        catch (InvalidPayloadException $ex) {
            $this->assertSame('Unable to find key "username" in the token payload.', $ex->getMessageKey());
        }
    }

    public function testGetUserWithInvalidUserThrowsException()
    {
        $decodedToken = new JsonWebToken(null, 'rawToken');
        $decodedToken->setPayload(array('username' => 'jameskirk'));

        $userProvider = $this->getUserProviderMock();
        $userProvider->expects($this->once())
            ->method('loadUserByUsername')
            ->with('jameskirk')
            ->willThrowException(new UsernameNotFoundException());

        try {
            $jwtManager = $this->getJsonWebTokenManagerMock('username', 'jameskirk');
            $dispatcher = $this->getEventDispatcherMock();
            $jwtTokenAuthenticator = new JwtTokenAuthenticator($jwtManager, $dispatcher, $this->getTokenExtractorMock());
            $jwtTokenAuthenticator->getUser($decodedToken, $userProvider);

            $this->fail(sprintf('Expected exception of type "%s" to be thrown.', UserNotFoundException::class));
        }
        catch (UserNotFoundException $ex) {
            $this->assertSame('Unable to load user with property "username" = "jameskirk". If the user identity has changed, you must renew the token. Otherwise, verify that the "rhapsody_security.jwt.claims.identity_claim" configuration option is set correctly.', $ex->getMessageKey());
        }
    }

    public function testCreateAuthenticatedToken()
    {
        $rawToken = 'token';
        $userRoles = ['ROLE_CAPTAIN'];
        $payload = ['username' => 'jameskirk'];
        $userStub = new UserFixture('jameskirk', 'password', 'jameskirk@enterprise.starfleet.fed', $userRoles);

        $decodedToken = new JsonWebToken(null, $rawToken);
        $decodedToken->setPayload($payload);

        $authenticatedToken = new JsonWebToken($userStub, $rawToken, 'rhapsody', $userRoles);
        $authenticatedToken->setPayload($payload);

        $jwtManager = $this->getJsonWebTokenManagerMock('username', 'jameskirk');

        $userProvider = $this->getUserProviderMock();
        $userProvider->expects($this->once())
            ->method('loadUserByUsername')
            ->with('jameskirk')
            ->willReturn($userStub);

        $dispatcher = $this->getEventDispatcherMock();
        $dispatcher->expects($this->once())
            ->method('dispatch')
            ->with(RhapsodySecurityEvents::JWT_AUTHENTICATED, new JwtAuthenticatedEvent($payload, $authenticatedToken));

        $authenticator = new JwtTokenAuthenticator($jwtManager, $dispatcher, $this->getTokenExtractorMock());

        $authenticator->getUser($decodedToken, $userProvider);

        $actual = $authenticator->createAuthenticatedToken($userStub, 'rhapsody');
        $this->assertEquals($authenticatedToken, $actual);
    }

    /**
     * @expectedException \RuntimeException
     * @expectedExceptionMessage Unable to return an authenticated token
     */
    public function testCreateAuthenticatedTokenThrowsExceptionIfNotPreAuthenticatedToken()
    {
        $userStub = new UserFixture('jameskirk', 'password');

        $jwtTokenAuthenticator = new JwtTokenAuthenticator($this->getJsonWebTokenManagerMock(), $this->getEventDispatcherMock(), $this->getTokenExtractorMock());
        $jwtTokenAuthenticator->createAuthenticatedToken($userStub, 'rhapsody');
    }

    public function testOnAuthenticationFailureWithInvalidToken()
    {
        $authException = new InvalidTokenException();
        $expectedResponse = new JwtAuthenticationFailureResponse('Invalid Token');

        $dispatcher = $this->getEventDispatcherMock();
        $dispatcher->expects($this->once())
            ->method('dispatch')
            ->with(RhapsodySecurityEvents::JWT_INVALID, new JwtInvalidEvent($authException, $expectedResponse));

        $authenticator = new JwtTokenAuthenticator($this->getJsonWebTokenManagerMock(), $dispatcher, $this->getTokenExtractorMock());

        $response = $authenticator->onAuthenticationFailure($this->getRequestMock(), $authException);

        $this->assertEquals($expectedResponse, $response);
        $this->assertSame($expectedResponse->getMessage(), $response->getMessage());
    }

    public function testStart()
    {
        $authException = new MissingTokenException('JWT Token not found');
        $failureResponse = new JwtAuthenticationFailureResponse($authException->getMessageKey());

        $dispatcher = $this->getEventDispatcherMock();
        $dispatcher->expects($this->once())
            ->method('dispatch')
            ->with(RhapsodySecurityEvents::JWT_NOT_FOUND, new JwtNotFoundEvent($authException, $failureResponse));

        $authenticator = new JwtTokenAuthenticator($this->getJsonWebTokenManagerMock(), $dispatcher, $this->getTokenExtractorMock());

        $response = $authenticator->start($this->getRequestMock());

        $this->assertEquals($failureResponse, $response);
        $this->assertSame($failureResponse->getMessage(), $response->getMessage());
    }

    public function testCheckCredentials()
    {
        $user = new UserFixture('test', 'test');

        $jwtTokenAuthenticator = new JwtTokenAuthenticator($this->getJsonWebTokenManagerMock(), $this->getEventDispatcherMock(), $this->getTokenExtractorMock());
        $this->assertTrue($jwtTokenAuthenticator->checkCredentials(null, $user));
    }

    public function testSupportsRememberMe()
    {
        $jwtTokenAuthenticator = new JwtTokenAuthenticator($this->getJsonWebTokenManagerMock(), $this->getEventDispatcherMock(), $this->getTokenExtractorMock());
        $this->assertFalse($jwtTokenAuthenticator->supportsRememberMe());
    }
}
