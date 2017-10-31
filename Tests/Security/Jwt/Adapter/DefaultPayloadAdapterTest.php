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
namespace Rhapsody\SecurityBundle\Tests\Security\Jwt\Adapter;

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\Security\Jwt\Adapter\DefaultPayloadAdapter;
use Rhapsody\SecurityBundle\Security\Jwt\Claim;
use Rhapsody\SecurityBundle\Tests\Fixtures\User;

/**
 *
 * @author    Sean W. Quinn <sean.quinn@extesla.com>
 * @category  Rhapsody SecurityBundle
 * @package   Rhapsody\SecurityBundle\Tests\Security\Jwt\Adapter
 * @copyright Rhapsody Project
 * @version   $Id$
 * @since     1.0
 */
class DefaultPayloadAdapterTest extends TestCase
{

    public function testCreatePayload()
    {
        $payloadAdapter = new DefaultPayloadAdapter();

        $user = new User('jameskirk', 'enterprise', 'jameskirk@enterprise.starfleet.fed', array('ROLE_CAPTAIN'));
        $user->setId(1);

        $claims = array(
            'identity' => new Claim('username', 'username', true),
            'email'    => new Claim('roles', 'roles'),
            'roles'    => new Claim('email', 'email', true),
            'subject'  => new Claim('sub', 'id', true),
        );

        $actual = $payloadAdapter->createPayload($user, $claims);
        $this->assertNotEmpty($actual);
        $this->assertEquals(array(
            'username' => 'jameskirk',
            'roles' => ['ROLE_CAPTAIN'],
            'email' => 'jameskirk@enterprise.starfleet.fed',
            'sub' => '1'
        ), $actual);
    }

}
