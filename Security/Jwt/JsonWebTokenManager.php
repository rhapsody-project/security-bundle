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
namespace Rhapsody\SecurityBundle\Security\Jwt;

use Monolog\Logger;
use Rhapsody\SecurityBundle\RhapsodySecurityEvents;
use Rhapsody\SecurityBundle\Security\Jwt\Adapter\PayloadAdapterInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebToken;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebTokenInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Encoder\JwtEncoderInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtCreatedEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtEncodedEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\InvalidPayloadException;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\Security\Core\User\UserInterface;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtDecodedEvent;

/**
 *
 * @author sean.quinn
 *
 */
class JsonWebTokenManager implements JsonWebTokenManagerInterface
{

    /**
     * All of the claims that have been configured with the JSON Web Token
     * manager and that will be passed to the payload adapter when creating
     * or decoding a JWT.
     * @var ClaimInterface[]
     */
    private $claims = array();

    /**
     *
     * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface
     */
    private $eventDispatcher;

    /**
     * The ID of the claim that will represent the user's identity, e.g.
     * <code>identity</code>.
     * @var string
     */
    private $identityClaim = 'identity';

    /**
     *
     * @var \Rhapsody\SecurityBundle\Security\Jwt\Encoder\JwtEncoderInterface
     */
    private $jwtEncoder;


    /**
     * The logging aparatus for this manager.
     * @var \Monolog\Logger
     */
    private $log;

    /**
     *
     * @var \Rhapsody\SecurityBundle\Security\Jwt\Adapter\PayloadAdapterInterface
     */
    private $payloadAdapter;

    public function __construct(JwtEncoderInterface $jwtEncoder, PayloadAdapterInterface $payloadAdapter, EventDispatcherInterface $eventDispatcher)
    {
        $this->log = new Logger(JsonWebTokenManager::class);
        $this->claims = array();

        $this->jwtEncoder = $jwtEncoder;
        $this->payloadAdapter = $payloadAdapter;
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * Adds a <code>$claim</code> to the list of known claims.
     *
     * @param string $id The claim identifier.
     * @param ClaimInterface $claim The claim.
     * @throws \InvalidArgumentException
     *     When a claim is added with an <code>$id</code> that has already been
     *     registered with the list of claims.
     * @return \Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManager
     */
    public function addClaim($id, ClaimInterface $claim)
    {
        if (isset($this->claims[$id])) {
            throw new \InvalidArgumentException(sprintf('The claim with ID: %s has already been registered.', $id));
        }
        $this->claims[$id] = $claim;
        return $this;
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface::getClaim()
     */
    public function getClaim($claim)
    {
        if ($this->hasClaim($claim)) {
            return $this->claims[$claim];
        }
        return null;
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface::getClaims()
     */
    public function getClaims()
    {
        return $this->claims;
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface::getIdentityClaim()
     */
    public function getIdentityClaim()
    {
        return $this->identityClaim;
    }

    /**
     * Return <code>true</code> if a <code>ClaimInterface</code> with the given
     * <code>$claim</code> identifier exists in the collection of registered
     * <code>$claims</code>; otherwise <code>false</code>.
     *
     * @param string $claim the claim identifier.
     * @return bool <code>true</code> if a claim exists with the given claim
     *     identifier; otherwise <code>false</code>.
     */
    public function hasClaim($claim)
    {
        return isset($this->claims[$claim]);
    }

    /**
     *
     * @param UserInterface $user
     * @param array $payload
     */
    protected function addUserIdentityToPayload(UserInterface $user, array &$payload)
    {
        $accessor = PropertyAccess::createPropertyAccessor();

        $identity = $accessor->getValue($user, $this->identityFieldName);
        $payload[$this->identityFieldName] = $identity;
    }

    /**
     *
     * @param UserInterface $user
     * @param array $payload
     */
    protected function addUserRolesToPayload(UserInterface $user, array &$payload)
    {
        $accessor = PropertyAccess::createPropertyAccessor();

        $roles = $accessor->getValue($user, $this->rolesFieldName);
        $payload[$this->rolesFieldName] = $roles;
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\JwtManagerInterface::createRefreshToken()
     */
    public function createRefreshToken()
    {
        //$refreshToken = new JwtRefreshToken();
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\JwtManagerInterface::createToken()
     */
    public function createToken(UserInterface $user)
    {
        $payload = $this->payloadAdapter->createPayload($user, $this->claims);
        $this->validate($payload);

        $jwtCreatedEvent = new JwtCreatedEvent($payload, $user);
        $this->eventDispatcher->dispatch(RhapsodySecurityEvents::JWT_CREATED, $jwtCreatedEvent);

        $rawToken = $this->jwtEncoder->encode($jwtCreatedEvent->getData());
        $this->eventDispatcher->dispatch(RhapsodySecurityEvents::JWT_ENCODED, new JwtEncodedEvent($rawToken));

        $token = new JsonWebToken($user, $rawToken, null, $user->getRoles());
        $token->setPayload($jwtCreatedEvent->getData());
        return $token;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface::decode()
     */
    public function decode($token)
    {
        $rawToken = $token;
        if ($token instanceof JsonWebTokenInterface) {
            $rawToken = $token->getCredentials();
        }

        $payload = $this->jwtEncoder->decode($rawToken);
        if (empty($payload)) {
            return false;
        }

        $event = new JwtDecodedEvent($payload);
        $this->eventDispatcher->dispatch(RhapsodySecurityEvents::JWT_DECODED, $event);
        if (!$event->isValid()) {
            return false;
        }
        return $payload;
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface::getUserIdentityFromToken()
     */
    public function getUserIdentityFromToken(JsonWebTokenInterface $jwt)
    {
        return $this->getUserIdentityFromPayload($jwt->getPayload());
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface::getUserIdentityFromPayload()
     */
    public function getUserIdentityFromPayload(array $payload = array())
    {
        $claim = $this->getClaim($this->identityClaim);
        if (null === $claim || !isset($payload[$claim->getName()])) {
            throw new InvalidPayloadException($this->identityClaim);
        }

        return $payload[$claim->getName()];
    }

    public function setClaims($claims)
    {
        foreach ($claims as $id => $claim) {
            $this->addClaim($id, $claim);
        }
    }

    /**
     * Assigns the <code>$identityClaim</code> lookup key to the passed
     * <code>$claim</code>.
     *
     * @param string $claim The key to lookup the user's identity claim by.
     */
    public function setIdentityClaim($claim)
    {
        $this->identityClaim = $claim;
    }

    /**
     * Validates that a <code>$payload</code> has an identity claim and that
     * all required claims are present.
     *
     * @param array $payload
     * @throws InvalidPayloadException If the payload is not valid.
     * @return boolean
     */
    public function validate($payload)
    {
        $claim = $this->getClaim($this->identityClaim);
        if (null === $claim || !isset($payload[$claim->getName()])) {
            throw new InvalidPayloadException($this->identityClaim);
        }

        // **
        // Verify that all required claims are in the payload, otherwise raise
        // and error indicating that the claim is missing. [SWQ]
        foreach ($this->claims as $claim) {
            if ($claim->isRequired() && !isset($payload[$claim->getName()])) {
                throw new InvalidPayloadException($claim->getName());
            }
        }

        return true;
    }
}