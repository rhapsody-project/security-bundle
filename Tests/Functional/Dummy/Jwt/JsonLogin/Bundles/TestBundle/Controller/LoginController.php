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
namespace Rhapsody\SecurityBundle\Tests\Functional\Dummy\Jwt\JsonLogin\Bundles\TestBundle\Controller;

use Rhapsody\SecurityBundle\RhapsodySecurityEvents;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtRefreshedEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Response\JwtAuthenticationSuccessResponse;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Security;

/**
 *
 * @author sean.quinn
 */
class LoginController extends Controller
{

    // public function loginAction(Request $request, UserInterface $user = null)
    public function loginAction(Request $request)
    {
        // get the login error if there is one
        if ($request->attributes->has(Security::AUTHENTICATION_ERROR)) {
            $error = $request->attributes->get(Security::AUTHENTICATION_ERROR);
        }
        else {
            $error = $request->getSession()->get(Security::AUTHENTICATION_ERROR);
        }

        return $this->render('TestBundle:Login:login.html.twig', array(
            'last_username' => $request->getSession()->get(Security::LAST_USERNAME),
            'error' => $error
        ));
    }

    public function afterLoginAction(Request $request)
    {
        $user = $this->getUser();
        return $this->render('TestBundle:Login:after_login.html.twig', array(
            'user' => $user
        ));
    }

    public function homepageAction(Request $request)
    {
        return new Response('Homepage');
    }

    public function loginCheckAction(Request $request)
    {
        throw new \RuntimeException('You must configure the check path to be handled by the firewall using json_login in your security firewall configuration.');
    }

    public function profileAction(Request $request)
    {
        return new Response('Profile');
    }

    public function refreshAction(Request $request)
    {
        /** @var $eventDispatcher \Symfony\Component\EventDispatcher\EventDispatcherInterface */
        $eventDispatcher = $this->get('event_dispatcher');

        /** @var $jsonWebTokenManager \Rhapsody\SecurityBundle\Security\Jwt\JsonWebTokenManagerInterface */
        $jsonWebTokenManager = $this->get('rhapsody_security.jwt_manager');

        // ** Create the refreshed token
        $refreshedToken = $jsonWebTokenManager->createToken($this->getUser());
        $response = new JwtAuthenticationSuccessResponse($refreshedToken);
        $event = new JwtRefreshedEvent(['token' => $refreshedToken->getCredentials()], $refreshedToken->getUser(), $response);
        $eventDispatcher->dispatch(RhapsodySecurityEvents::JWT_REFRESHED, $event);
        $response->setData($event->getData());
        return $response;
    }

    public function secureAction(Request $request)
    {
        throw new \Exception('Wrapper', 0, new \Exception('Another Wrapper', 0, new AccessDeniedException()));
    }
}
