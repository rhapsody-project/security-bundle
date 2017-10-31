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
namespace Rhapsody\SecurityBundle\Tests\Security\Jwt\Event;

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtAuthenticatedEvent;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class JwtAuthenticatedEventTest extends TestCase
{

    public function testConstructor()
    {
        $event = new JwtAuthenticatedEvent(array('foo' => 'bar'), $this->createMock(TokenInterface::class));

        $this->assertNotEmpty($event->getPayload());
        $this->assertInstanceOf(TokenInterface::class, $event->getToken());
    }

    public function testGetPayload()
    {
        $event = new JwtAuthenticatedEvent(array('foo' => 'bar'), $this->createMock(TokenInterface::class));
        $this->assertEquals(array('foo' => 'bar'), $event->getPayload());
    }

    public function testGetToken()
    {
        $event = new JwtAuthenticatedEvent(array('foo' => 'bar'), $this->createMock(TokenInterface::class));
        $this->assertInstanceOf(TokenInterface::class, $event->getToken());
    }

    public function testSetPayload()
    {
        $event = new JwtAuthenticatedEvent(array(), $this->createMock(TokenInterface::class));
        $this->assertEmpty($event->getPayload());

        $event->setPayload(array('foo' => 'bar'));
        $this->assertEquals(array('foo' => 'bar'), $event->getPayload());
    }
}
