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
namespace Rhapsody\SecurityBundle\Security\Jwt\RememberMe;

use Rhapsody\SecurityBundle\Security\Jwt\RememberMe\AbstractJwtRememberMeServices;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 *
 * @author sean.quinn
 */
class SimpleJwtRememberMeServices extends AbstractJwtRememberMeServices
{

    /**
     */
    protected function processAutoLoginToken($payload, Request $request)
    {
        $username = $this->jsonWebTokenManager->getUserIdentityFromPayload($payload);
        try {
            $user = $this->userProvider->loadUserByUsername($username);
        }
        catch (\Exception $ex) {
            if (!$ex instanceof AuthenticationException) {
                $ex = new AuthenticationException($ex->getMessage(), $ex->getCode(), $ex);
            }
            throw $ex;
        }

        if (!$user instanceof UserInterface) {
            throw new \RuntimeException(sprintf('The UserProviderInterface implementation must return an instance of UserInterface, but returned "%s".', get_class($user)));
        }
        return $user;
    }

    protected function onLoginFail(Request $request)
    {
        // TODO: loginFailure (unlike loginSuccess, below) should clear out any
        //       prospective traces of a user in the system appropriately. E.g.
        //       session-or-persistant tokens should be cleared.
        //
        //       There should be none of this left around for a Simple JWT
        //       though so... no op!
    }

    protected function onLoginSuccess(Request $request, Response $response, TokenInterface $token)
    {
        // TODO: loginSuccess would be called from an authentication listener, e.g.
        //       GuardAuthenticationListener, after authentication success if the
        //       guard/authentication scheme supported remember me. This would
        //       allow us to do *something* with remember me services.
        //
        //       For the benefit of a "simple" refresh service, this would do
        //       nothing as remember me is really just a "re-auth" before tokens
        //       expire.
        //
        //       For a session or persistent refresh token however, one that lives
        //       outside of the ephemeral memory of the client, it might make sense
        //       to react and create an entry in token storage, the database, or
        //       both.
    }
}