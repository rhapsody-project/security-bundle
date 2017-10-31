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
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtInvalidEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Exception\InvalidTokenException;
use Symfony\Component\HttpFoundation\Response;

class JwtInvalidEventTest extends TestCase
{

    public function testConstructor()
    {
        $event = new JwtInvalidEvent(new InvalidTokenException(), $this->createMock(Response::class));

        $this->assertNotEmpty($event->getException());
        $this->assertNotEmpty($event->getResponse());
    }

    public function testGetException()
    {
        $event = new JwtInvalidEvent(new InvalidTokenException(), $this->createMock(Response::class));

        $actual = $event->getException();
        $this->assertInstanceOf(InvalidTokenException::class, $actual);
        $this->assertEquals('Invalid Token', $actual->getMessageKey());
    }

    public function testGetResponse()
    {
        $event = new JwtInvalidEvent(new InvalidTokenException(), $this->createMock(Response::class));

        $actual = $event->getResponse();
        $this->assertInstanceOf(Response::class, $actual);
    }

}
