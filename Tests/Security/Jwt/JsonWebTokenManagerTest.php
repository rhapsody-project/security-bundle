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
namespace Rhapsody\SecurityBundle\Tests\Security\Jwt;

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\RhapsodySecurityEvents;
use Rhapsody\SecurityBundle\Security\Jwt\Adapter\PayloadAdapterInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebToken;
use Rhapsody\SecurityBundle\Security\Jwt\Claim;
use Rhapsody\SecurityBundle\Security\Jwt\Encoder\JwtEncoderInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtCreatedEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtDecodedEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtEncodedEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\JwtDecodeFailureException;
use Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManager;
use Rhapsody\SecurityBundle\Tests\Fixtures\User;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class JsonWebTokenManagerTest extends TestCase
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
     * Returns a mock <code>JwtEncoderInterface</code>.
     *
     * @return \PHPUnit_Framework_MockObject_MockObject a mock JWT encoder.
     */
    private function getJwtEncoder()
    {
        $encoder = $this->getMockBuilder(JwtEncoderInterface::class)
            ->getMock();
        return $encoder;
    }

    /**
     * Returns a mock <code>PayloadAdapterInterface</code> for testing.
     *
     * @return \PHPUnit_Framework_MockObject_MockObject a mock payload adapter.
     */
    private function getPayloadAdapter()
    {
        $payloadAdapter = $this->getMockBuilder(PayloadAdapterInterface::class)
            ->getMock();
        return $payloadAdapter;
    }

    public function testAddClaim()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->addClaim('foo', new Claim('foo', 'bar'));
        $manager->addClaim('baz', new Claim('baz', 'baz', true));

        $actual = $manager->getClaim('foo');
        $this->assertNotNull($actual);
        $this->assertEquals('foo', $actual->getName());
        $this->assertEquals('bar', $actual->getProperty());
        $this->assertFalse($actual->isRequired());

        $actual = $manager->getClaim('baz');
        $this->assertNotNull($actual);
        $this->assertEquals('baz', $actual->getName());
        $this->assertEquals('baz', $actual->getProperty());
        $this->assertTrue($actual->isRequired());
    }

    /**
     * @expectedException \TypeError
     */
    public function testAddClaimThatDoesNotImplementClaimInterface()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->addClaim('user', new \stdClass());
    }

    public function testCreateToken()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $user = new User('jameskirk', 'enterprise', 'jameskirk@enterprise.starfleet.fed', array('ROLE_CAPTAIN'));
        $user->setId(1);

        $claims = array(
            'identity' => new Claim('username', 'username', true),
            'roles'    => new Claim('roles', 'roles'),
            'email'    => new Claim('email', 'email'),
            'subject'  => new Claim('sub', 'id'));

        $payload = array(
            'username' => 'jameskirk',
            'roles'    => ['ROLE_CAPTAIN'],
            'email'    => 'jameskirk@enterprise.starfleet.fed',
            'sub'      => 1);

        $jwtEncoder->expects($this->once())
            ->method('encode')
            ->with($payload)
            ->willReturn('token');

        $payloadAdapter->expects($this->once())
            ->method('createPayload')
            ->with($this->isInstanceOf(UserInterface::class), $claims)
            ->willReturn($payload);

        $eventDispatcher->expects($this->exactly(2))
            ->method('dispatch')
            ->withConsecutive(
                [RhapsodySecurityEvents::JWT_CREATED, new JwtCreatedEvent($payload, $user)],
                [RhapsodySecurityEvents::JWT_ENCODED, new JwtEncodedEvent('token')]);

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->setClaims($claims);
        $manager->setIdentityClaim('identity');

        $actual = $manager->createToken($user);
        $this->assertNotEmpty($actual);
        $this->assertEquals('token', $actual->getRawToken());
        $this->assertSame($user, $actual->getUser());
        $this->assertSame($payload, $actual->getPayload());
    }

    public function testDecode()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $token = new JsonWebToken(null, 'token');
        $payload = array('foo' => 'bar');
        $event = new JwtDecodedEvent($payload);

        $jwtEncoder->expects($this->once())
            ->method('decode')
            ->with('token')
            ->willReturn($payload);

        $eventDispatcher->expects($this->once())
            ->method('dispatch')
            ->with(RhapsodySecurityEvents::JWT_DECODED, $event);

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $actual = $manager->decode($token);
        $this->assertEquals(array('foo' => 'bar'), $actual);
    }

    public function testDecodeReturnsFalseForEmptyPayload()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $token = new JsonWebToken(null, 'token');
        $jwtEncoder->expects($this->once())
            ->method('decode')
            ->with('token')
            ->willReturn(array());

        $eventDispatcher->expects($this->never())->method('dispatch');

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $this->assertFalse($manager->decode($token));
    }

    /**
     * @expectedException \Rhapsody\SecurityBundle\Security\Jwt\Exception\JwtDecodeFailureException
     */
    public function testDecodeRaisesExceptionWhenEncoderFailsToLoadSignatureFromToken()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $token = new JsonWebToken(null, 'token');
        $jwtEncoder->expects($this->once())
            ->method('decode')
            ->with('token')
            ->willThrowException(new JwtDecodeFailureException(JwtDecodeFailureException::INVALID_TOKEN));

        $eventDispatcher->expects($this->never())->method('dispatch');

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->decode($token);
    }

    /**
     * @expectedException \Rhapsody\SecurityBundle\Security\Jwt\Exception\JwtDecodeFailureException
     */
    public function testDecodeRaisesExceptionWhenSignatureIsInvalid()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $token = new JsonWebToken(null, 'token');
        $jwtEncoder->expects($this->once())
            ->method('decode')
            ->with('token')
            ->willThrowException(new JwtDecodeFailureException(JwtDecodeFailureException::INVALID_TOKEN));

        $eventDispatcher->expects($this->never())->method('dispatch');

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->decode($token);
    }

    /**
     * @expectedException \Rhapsody\SecurityBundle\Security\Jwt\Exception\JwtDecodeFailureException
     */
    public function testDecodeRaisesExceptionWhenTokenIsExpired()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $token = new JsonWebToken(null, 'token');
        $jwtEncoder->expects($this->once())
            ->method('decode')
            ->with('token')
            ->willThrowException(new JwtDecodeFailureException(JwtDecodeFailureException::EXPIRED_TOKEN));

        $eventDispatcher->expects($this->never())->method('dispatch');

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->decode($token);
    }

    /**
     * @expectedException \Rhapsody\SecurityBundle\Security\Jwt\Exception\JwtDecodeFailureException
     */
    public function testDecodeRaisesExceptionWhenSignatureIsUnverified()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $token = new JsonWebToken(null, 'token');
        $jwtEncoder->expects($this->once())
            ->method('decode')
            ->with('token')
            ->willThrowException(new JwtDecodeFailureException(JwtDecodeFailureException::UNVERIFIED_TOKEN));

        $eventDispatcher->expects($this->never())->method('dispatch');

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->decode($token);
    }

    public function testGetClaim()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->addClaim('foo', new Claim('foo', 'bar'));

        $actual = $manager->getClaim('foo');
        $this->assertNotNull($actual);
        $this->assertEquals('foo', $actual->getName());
        $this->assertEquals('bar', $actual->getProperty());
        $this->assertFalse($actual->isRequired());
    }

    public function testGetClaimWhenClaimDoesNotExist()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->addClaim('foo', new Claim('foo', 'bar'));

        $actual = $manager->getClaim('baz');
        $this->assertNull($actual);
    }

    public function testHasClaimReturnsFalseForUnknownClaim()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->addClaim('foo', new Claim('foo', 'bar'));
        $this->assertFalse($manager->hasClaim('baz'));
    }

    public function testHasClaimReturnsTrueForKnownClaim()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->addClaim('foo', new Claim('foo', 'bar'));
        $this->assertTrue($manager->hasClaim('foo'));
    }

    public function testSetClaims()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $claims = array(
            'identity' => new Claim('username', 'username', true),
            'foo'      => new Claim('foo', 'bar'));

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->setClaims($claims);

        $actual = $manager->getClaims();
        $this->assertNotEmpty($actual);
        $this->assertCount(2, $actual);
        $this->assertArrayHasKey('identity', $actual);
        $this->assertArrayHasKey('foo', $actual);

        $actual = $manager->getClaim('identity');
        $this->assertNotNull($actual);
        $this->assertEquals('username', $actual->getName());
        $this->assertEquals('username', $actual->getProperty());

        $actual = $manager->getClaim('foo');
        $this->assertNotNull($actual);
        $this->assertEquals('foo', $actual->getName());
        $this->assertEquals('bar', $actual->getProperty());
    }

    public function setIdentityClaim()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $claims = array(
            'identity' => new Claim('username', 'username', true),
            'foo'      => new Claim('foo', 'bar'));

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->setIdentityClaim('identity');

        $actual = $manager->getIdentityClaim();
        $this->assertNotEmpty($actual);
        $this->assertEquals('identity', $actual);
    }

    /**
     * @expectedException \Rhapsody\SecurityBundle\Security\Jwt\Exception\InvalidPayloadException
     * @expectedExceptionMessage Unable to find key "identity" in the token payload.
     */
    public function testValidateEmptyPayload()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->setIdentityClaim('identity');

        $manager->validate(array());
    }

    public function testValidatePayload()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->setIdentityClaim('identity');
        $manager->addClaim('identity', new Claim('username', 'username', true));
        $manager->addClaim('roles', new Claim('roles', 'roles'));
        $manager->addClaim('subject', new Claim('sub', 'id', true));

        $actual = $manager->validate(array(
            'username' => 'jameskirk',
            'roles' => array('ROLE_USER'),
            'sub' => 1
        ));
        $this->assertTrue($actual);
    }

    /**
     * @expectedException \Rhapsody\SecurityBundle\Security\Jwt\Exception\InvalidPayloadException
     * @expectedExceptionMessage Unable to find key "identity" in the token payload.
     */
    public function testValidatePayloadWithoutIdentityClaim()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->setIdentityClaim('identity');
        $manager->addClaim('user', new Claim('user', 'username'));
        $manager->addClaim('foo', new Claim('foo', 'foo', true));

        $manager->validate(array(
            'user' => 'jameskirk',
            'foo'  => 'bar'
        ));
    }

    /**
     * @expectedException \Rhapsody\SecurityBundle\Security\Jwt\Exception\InvalidPayloadException
     * @expectedExceptionMessage Unable to find key "foo" in the token payload.
     */
    public function testValidatePayloadWithoutOtherRequiredClaims()
    {
        $jwtEncoder = $this->getJwtEncoder();
        $payloadAdapter = $this->getPayloadAdapter();
        $eventDispatcher = $this->getEventDispatcher();

        $manager = new JsonWebTokenManager($jwtEncoder, $payloadAdapter, $eventDispatcher);
        $manager->setIdentityClaim('identity');
        $manager->addClaim('identity', new Claim('username', 'username'));
        $manager->addClaim('foo', new Claim('foo', 'foo', true));

        $manager->validate(array(
            'username' => 'jameskirk'
        ));
    }
}