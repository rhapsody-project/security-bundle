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
namespace Rhapsody\SecurityBundle\Security\Http\Firewall;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PropertyAccess\Exception\AccessException;
use Symfony\Component\PropertyAccess\PropertyAccessorInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;

/**
 * A firewall that processes user authentication requests where a user's
 * credentials can be passed either as a username-password pair in a JSON
 * payload, or as a JSON Web Token (JWT).
 *
 * This firewall is based heavily upon the work of Fabien Potencier and Kevin
 * Dunglas found in the core Symfony Framework that exposes both form- and
 * JSON-based login firewalls.
 *
 * The <code>jwt_login</code> firewall, represented by this authentication
 * listener class, was added as a JWT-friendly alternative to the already
 * existing <code>UsernamePasswordJsonAuthenticationListener</code> introduced
 * by Kevin Dunglas in <a href="https://github.com/symfony/symfony/pull/18952">PR-18952</a>
 * which may be used to handle JWT authentication (as illustrated by tests in
 * this bundle).
 *
 * This authentication listener uses the <code>AbstractAuthenticationListener</code>
 * for the majority of its code.
 *
 * @author    Sean W. Quinn <sean.quinn@extesla.com>
 * @category  Rhapsody SecurityBundle
 * @package   Rhapsody\SecurityBundle\Security\Http\Firewall
 * @copyright Rhapsody Project
 * @version   $Id$
 * @since     1.0
 */
class UsernamePasswordJwtAuthenticationListener extends AbstractAuthenticationListener
{

    /**
     *
     * @var \Symfony\Component\PropertyAccess\PropertyAccessorInterface
     */
    private $propertyAccessor;

    /**
     *
     * @param TokenStorageInterface $tokenStorage
     * @param AuthenticationManagerInterface $authenticationManager
     * @param SessionAuthenticationStrategyInterface $sessionStrategy
     * @param HttpUtils $httpUtils
     * @param unknown $providerKey
     * @param AuthenticationSuccessHandlerInterface $successHandler
     * @param AuthenticationFailureHandlerInterface $failureHandler
     * @param array $options
     * @param LoggerInterface $logger
     * @param EventDispatcherInterface $dispatcher
     * @param PropertyAccessorInterface $propertyAccessor
     */
    public function __construct(TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, $providerKey, AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler, array $options = array(), LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null, PropertyAccessorInterface $propertyAccessor = null)
    {
        parent::__construct($tokenStorage, $authenticationManager, $sessionStrategy, $httpUtils, $providerKey, $successHandler, $failureHandler, array_merge(array(
            'username_path' => '_username',
            'password_path' => '_password',
            'post_only' => true,
        ), $options), $logger, $dispatcher);
        $this->propertyAccessor = $propertyAccessor ?: PropertyAccess::createPropertyAccessor();
    }

    protected function attemptAuthentication(Request $request)
    {
        $data = json_decode($request->getContent());

        if (!$data instanceof \stdClass) {
            throw new BadCredentialsException('Invalid JSON.');
        }

        $username = $this->getCredentialsProperty($data, $this->options['username_path']);
        $password = $this->getCredentialsProperty($data, $this->options['password_path']);

        if (!is_string($username)) {
            throw new BadCredentialsException(sprintf('The key "%s" must be a string.', $this->options['username_path']));
        }

        if (strlen($username) > Security::MAX_USERNAME_LENGTH) {
            throw new BadCredentialsException('Invalid username.');
        }

        if (!is_string($password)) {
            throw new BadCredentialsException(sprintf('The key "%s" must be a string.', $this->options['password_path']));
        }

        $request->getSession()->set(Security::LAST_USERNAME, $username);
        return $this->authenticationManager->authenticate(new UsernamePasswordToken($username, $password, $this->providerKey));
    }

    /**
     *
     * @param unknown $objectOrArray
     * @param unknown $propertyPath
     * @throws BadCredentialsException
     * @return mixed
     */
    private function getCredentialsProperty($objectOrArray, $propertyPath)
    {
        try {
            return $this->propertyAccessor->getValue($objectOrArray, $propertyPath);
        }
        catch (AccessException $ex) {
            throw new BadCredentialsException(sprintf('The key "%s" must be provided', $propertyPath));
        }
    }

    /**
     * Like the core <code>UsernamePasswordFormAuthenticationListener</code>,
     * the Rhapsody JSON authentication listener checks to see if the firewall
     * was configured handling authentication on only requests made with the
     * <code>POST</code> method.
     *
     * If the <code>post_only</code> option is true, and a request to the
     * authentication firewall is made not using a POST method, then the
     * authentication request will be ignored.
     *
     * @param $request Symfony\Component\HttpFoundation\Request
     *     the request being made.
     * @return boolean <code>true</code> if the request requires authentication;
     *     otherwise <code>false</code>.
     * @see \Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener::requiresAuthentication()
     */
    protected function requiresAuthentication(Request $request)
    {
        if ($this->options['post_only'] && !$request->isMethod('POST')) {
            return false;
        }
        return parent::requiresAuthentication($request);
    }

}
