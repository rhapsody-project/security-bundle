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
namespace Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 *
 * @author sean.quinn
 *
 */
class JsonWebToken extends AbstractToken implements JsonWebTokenInterface
{

    /**
     *
     * @var unknown
     */
    private $payload;

    /**
     *
     * @var unknown
     */
    private $providerKey;

    /**
     * The Base64 encoded JWT token containing the <code>header</code>,
     * <code>payload</code>, and <code>signature</code>.
     *
     * @var string
     */
    private $rawToken;

    /**
     * A static function for conveniently creating a <code>JsonWebToken</code>
     * from a raw token string.
     *
     * @param string $rawToken The raw JSON web token string.
     * @param string $providerKey The provider (firewall) key.
     * @return \Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebToken
     *     The {@link JsonWebToken}.
     */
    public static function fromToken($rawToken, $providerKey = null)
    {
        return new JsonWebToken(null, $rawToken, $providerKey);
    }

    /**
     * A static function for conveniently creating a <code>JsonWebToken</code>
     * from a user.
     *
     * @param UserInterface|string $user The user.
     * @param string $providerKey The provider (firewall) key.
     * @return \Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebToken
     *     The {@link JsonWebToken}.
     */
    public static function fromUser($user, $providerKey = null)
    {
        if ($user instanceof UserInterface) {
            return new JsonWebToken($user, null, $providerKey, $user->getRoles());
        }
        return new JsonWebToken($user, null, $providerKey);
    }

    /*

     $jwtToken = new JsonWebToken($user, $providerKey);

     $payload = $jwtPayloadAdapter->create($jwtToken);
     $jwtToken->setPayload($payload);

     $token = $jwtEncoder->encode($jwtToken);
     $jwtToken->setToken($token);

     ---

     $payload = $jwtEncoder->decode($token);
     $user = // .. find user
     $jwtToken = new JsonWebToken($user, $providerKey);
     $jwtToken->setPayload($payload);
     $jwtToken->setToken($token);

     */
    public function __construct($user, $rawToken, $providerKey = null, array $roles = array())
    {
        parent::__construct($roles);

        if (null !== $user) {
            $this->setUser($user);
        }
        $this->rawToken = $rawToken;
        $this->providerKey = $providerKey;

        // FIXME: Is there a better way to set authenticated? Maybe only if $rawToken is provided?
        parent::setAuthenticated(true);
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials()
    {
        parent::eraseCredentials();
        $this->rawToken = null;
    }

    /**
     * {@inheritDoc}
     * @see \Symfony\Component\Security\Core\Authentication\Token\TokenInterface::getCredentials()
     */
    public function getCredentials()
    {
        return $this->rawToken;
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebTokenInterface::getPayload()
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * Returns the provider key.
     *
     * @return string The provider key
     */
    public function getProviderKey()
    {
        return $this->providerKey;
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebTokenInterface::getRawToken()
     */
    public function getRawToken()
    {
        return $this->rawToken;
    }

    /**
     * {@inheritDoc}
     * @see \Symfony\Component\Security\Core\Authentication\Token\AbstractToken::setAuthenticated()
     */
    public function setAuthenticated($isAuthenticated)
    {
        // NB: We're following a pattern used by Symfony Security core here,
        //     which is to prevent assignment of a trusted token after the
        //     token has been instantiated. There are other ways to handle
        //     this and, maybe we'll change this implementation but for now
        //     let's follow the example that Symfony Security sets. [SWQ]
        //
        // See Also:
        //    Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken::setAuthenticated()
        if ($isAuthenticated) {
            throw new \LogicException('Cannot set this token to trusted after instantiation.');
        }
        parent::setAuthenticated(false);
    }

    /**
     * Sets the
     * @param unknown $payload
     */
    public function setPayload(array $payload = array())
    {
        $this->payload = $payload;
    }

    /**
     * Assign the base 64 encoded token to this <code>JsonWebToken</code>.
     *
     * @param string $token
     */
    public function setRawToken($rawToken)
    {
       $this->rawToken = $rawToken;
    }
}
