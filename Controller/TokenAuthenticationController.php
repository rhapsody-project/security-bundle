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
namespace Rhapsody\SecurityBundle\Controller;

use Monolog\Logger;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Security;

/**
 *
 * @author    Sean W. Quinn <sean.quinn@extesla.com>
 * @category  Rhapsody SecurityBundle
 * @package   Rhapsody\SecurityBundle\Controller
 * @copyright Rhapsody Project
 * @version   $Id$
 * @since     1.0
 */
class TokenAuthenticationController extends Controller
{
    const FAILED_AUTHENTICATION_ATTEMPTS = 'lorecall.user.security.failed_authentication_attempts';

    /**
     * The logging aparatus for this controller.
     * @var \Monolog\Logger
     */
    protected $log;

    public function __construct()
    {
        $this->log = new Logger(get_class($this));
    }

    /**
     * The <code>authenticate</code> action should never be called directly;
     * instead it should be configured as the <code>check_path</code> for a
     * valid firewall (e.g. <code>form_login</code>, <code>json_login</code>,
     * etc.).
     *
     * If configured properly, all visits to the URL associated with the
     * <code>TokenAuthenticationController</code>'s <code>authenticate</code>
     * action will be passed directly into the firewall's authentication
     * listener and never hit the body of this method. If you have not
     * configured your authentication firewall correctly you will see a
     * <code>RuntimeException</code> raised informing you of the appropriate
     * response to take.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @throws \RuntimeException When your authentication firewall is not
     *     configured properly.
     */
    public function authenticateAction(Request $request)
    {
        throw new \RuntimeException('You must configure the authenticate action to be the route associated with the `check_path` for the authentication token firewall that is one of: form_login, json_login, or another compatible solution in your security firewall configuration.');
    }

    public function refreshAction(Request $request)
    {
        throw new \RuntimeException('You must configure the refresh authenticate action to be the route associated with the `check_path` for the refresh token firewall that is one of: form_login, json_login, or another compatible solution in your security firewall configuration.');
    }
}