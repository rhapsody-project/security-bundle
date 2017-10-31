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
namespace Rhapsody\SecurityBundle\Security\Http\RememberMe;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\RememberMe\RememberMeServicesInterface;

/**
 *
 * @author sean.quinn
 */
class ChainRememberMeServices implements \IteratorAggregate, RememberMeServicesInterface
{
    /**
     * The map of registered remember-me services.
     * @var array
     */
    private $map;

    /**
     * @param array $map
     */
    public function __construct(array $map)
    {
        $this->map = $map;
    }

    /**
     * Adds a new remember-me services entry to the map.
     *
     * @param RememberMeServicesInterface $rememberMeServices
     */
    public function addRememberMeServices(RememberMeServicesInterface $rememberMeServices)
    {
        $this->map[] = $rememberMeServices;
    }

    /**
     * Removes a remember-me services entry from the map.
     *
     * @param Closure $filter A function taking a remembe-me services instance
     *     as an argument, used to find the remembe-me services to remove.
     * @return bool <code>true</code> in case of success; otherwise
     *     <code>false</code>.
     */
    public function removeRememberMeServices(\Closure $filter)
    {
        $filtered = array_filter($this->map, $filter);

        if (!$rememberMeServicesToUnmap = current($filtered)) {
            return false;
        }

        $key = array_search($rememberMeServicesToUnmap, $this->map);
        unset($this->map[$key]);

        return true;
    }

    /**
     * Clears the remember-me services map.
     */
    public function clearMap()
    {
        $this->map = [];
    }

    /**
     * Iterates over the remember-me services map calling {@see ???()}
     * until a token successfully resolves the auto login process, or all
     * services are exhausted, whichever occurs first.
     *
     * {@inheritdoc}
     */
    public function autoLogin(Request $request)
    {
        foreach ($this->getIterator() as $rememberMeServices) {
            try {
                if ($token = $rememberMeServices->autoLogin($request)) {
                    return $token;
                }
            }
            catch (AuthenticationException $ex) {
                $rememberMeServices->loginFail($request);
            }
        }
    }

    /**
     * Iterates over the mapped remember-me services while generating them.
     *
     * A remember-me services entry is initialized only if we really need it
     * (at the corresponding iteration).
     *
     * @return \Generator The generated {@link RememberMeServicesInterface} implementations
     */
    public function getIterator()
    {
        foreach ($this->map as $rememberMeServices) {
            if ($rememberMeServices instanceof RememberMeServicesInterface) {
                yield $rememberMeServices;
            }
        }
    }

    /**
     * The <code>loginFail</code> method on a chain remember-me services is a
     * no-op, each remember me service cleans up if it is unsuccessful as the
     * <code>autoLogin</code> function iterates over the registered services.
     *
     * {@inheritDoc}
     */
    public function loginFail(Request $request)
    {
        // Empty. Calling login failure directly on a chain remember-me service does nothing.
    }

    /**
     * {@inheritDoc}
     * @see \Symfony\Component\Security\Http\RememberMe\RememberMeServicesInterface::loginSuccess()
     */
    public function loginSuccess(Request $request, Response $response, TokenInterface $token)
    {
        throw new \Exception();
    }
}