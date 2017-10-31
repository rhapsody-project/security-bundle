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
namespace Rhapsody\SecurityBundle\Tests\Security\Jwt\Authentication\Provider;

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Provider\JwtAuthenticationProvider;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebToken;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebTokenInterface;
use Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class JwtAuthenticationProviderTest extends TestCase
{

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject
     */
    private function getJsonWebTokenManagerMock()
    {
        $jwtManager = $this->getMockBuilder(JsonWebTokenManagerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        return $jwtManager;
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject
     */
    private function getUserCheckerMock()
    {
        $userChecker = $this->getMockBuilder(UserCheckerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        return $userChecker;
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject
     */
    private function getUserProviderMock()
    {
        $userProvider = $this->getMockBuilder(UserProviderInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        return $userProvider;
    }

    public function testAuthenticate()
    {
        $user = $this->createMock(UserInterface::class);
        $userProvider = $this->getUserProviderMock();
        $userProvider->expects($this->once())
            ->method('loadUserByUsername')
            ->with('jameskirk')
            ->willReturn($user);

        $userChecker = $this->getUserCheckerMock();
        $userChecker->expects($this->once())
            ->method('checkPreAuth')
            ->with($user);

        $jwtManager = $this->getJsonWebTokenManagerMock();
        $jwtManager->expects($this->once())
            ->method('getUserIdentityFromToken')
            ->with($this->isInstanceOf(JsonWebTokenInterface::class))
            ->willReturn('jameskirk');
        $jwtManager->expects($this->once())
            ->method('createToken')
            ->with($this->isInstanceOf(UserInterface::class))
            ->willReturn(new JsonWebToken($user, 'jwt', 'foo'));

        $token = new JsonWebToken(null, 'jwt', 'foo');
        $provider = new JwtAuthenticationProvider($userProvider, $userChecker, 'foo', $jwtManager);

        $actual = $provider->authenticate($token);
        $this->assertNotNull($actual);
        $this->assertInstanceOf(JsonWebTokenInterface::class, $actual);
        $this->assertSame($user, $actual->getUser());
        $this->assertSame('jwt', $actual->getCredentials());
    }

    /**
     * @expectedException \Symfony\Component\Security\Core\Exception\AuthenticationServiceException
     */
    public function testAuthenticateWhenUserRetrievalReturnsNull()
    {
        $userProvider = $this->getUserProviderMock();
        $userProvider->expects($this->once())
            ->method('loadUserByUsername')
            ->with('jameskirk')
            ->willReturn(null);

        $userChecker = $this->getUserCheckerMock();

        $jwtManager = $this->getJsonWebTokenManagerMock();
        $jwtManager->expects($this->once())
            ->method('getUserIdentityFromToken')
            ->with($this->isInstanceOf(JsonWebTokenInterface::class))
            ->willReturn('jameskirk');

        $token = new JsonWebToken(null, 'jwt', 'foo');
        $provider = new JwtAuthenticationProvider($userProvider, $userChecker, 'foo', $jwtManager);
        $provider->authenticate($token);
    }

    /**
     * @expectedException \Symfony\Component\Security\Core\Exception\UsernameNotFoundException
     */
    public function testAuthenticateWhenUserRetrievalThrowsUsernameNotFoundException()
    {
        $userProvider = $this->getUserProviderMock();
        $userProvider->expects($this->once())
            ->method('loadUserByUsername')
            ->with('jameskirk')
            ->willThrowException(new UsernameNotFoundException());

        $userChecker = $this->getUserCheckerMock();

        $jwtManager = $this->getJsonWebTokenManagerMock();
        $jwtManager->expects($this->once())
            ->method('getUserIdentityFromToken')
            ->with($this->isInstanceOf(JsonWebTokenInterface::class))
            ->willReturn('jameskirk');

        $token = new JsonWebToken(null, 'jwt', 'foo');
        $provider = new JwtAuthenticationProvider($userProvider, $userChecker, 'foo', $jwtManager);
        $provider->authenticate($token);
    }

    public function testSupportsFailsForJsonWebTokenWithDifferentProvider()
    {
        $userProvider = $this->getUserProviderMock();
        $userChecker = $this->getUserCheckerMock();
        $jwtManager = $this->getJsonWebTokenManagerMock();

        $provider = new JwtAuthenticationProvider($userProvider, $userChecker, 'bar', $jwtManager);
        $token = new JsonWebToken(null, 'jwt', 'foo');
        $actual = $provider->supports($token);
        $this->assertFalse($actual);
    }

    public function testSupportsFailsForNonJsonWebToken()
    {
        $userProvider = $this->getUserProviderMock();
        $userChecker = $this->getUserCheckerMock();
        $jwtManager = $this->getJsonWebTokenManagerMock();

        $provider = new JwtAuthenticationProvider($userProvider, $userChecker, 'foo', $jwtManager);
        $token = $this->getMockBuilder(TokenInterface::class)->getMock();
        $actual = $provider->supports($token);
        $this->assertFalse($actual);
    }

    public function testSupportsSucceedsForJsonWebTokenWithSameProvider()
    {
        $userProvider = $this->getUserProviderMock();
        $userChecker = $this->getUserCheckerMock();
        $jwtManager = $this->getJsonWebTokenManagerMock();

        $provider = new JwtAuthenticationProvider($userProvider, $userChecker, 'foo', $jwtManager);
        $token = new JsonWebToken(null, 'jwt', 'foo');
        $actual = $provider->supports($token);
        $this->assertTrue($actual);
    }

}
