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
namespace Rhapsody\SecurityBundle\Tests\Security\Jwt\Response;

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\Security\Jwt\Response\JwtAuthenticationFailureResponse;

/**
 *
 * @author sean.quinn
 *
 */
final class JwtAuthenticationFailureResponseTest extends TestCase
{
    public function testResponse()
    {
        $expected = [
            'code'    => 401,
            'message' => 'message',
        ];

        $response = new JwtAuthenticationFailureResponse($expected['message']);

        $this->assertSame($expected['message'], $response->getMessage());
        $this->assertSame($expected['code'], $response->getStatusCode());
        $this->assertSame('Bearer', $response->headers->get('WWW-Authenticate'));
        $this->assertSame(json_encode($expected), $response->getContent());

        return $response;
    }

    /**
     * @depends testResponse
     */
    public function testSetMessage(JwtAuthenticationFailureResponse $response)
    {
        $newMessage = 'new message';
        $response->setMessage($newMessage);

        $responseBody = json_decode($response->getContent());

        $this->assertSame($response->getStatusCode(), $responseBody->code);
        $this->assertSame($newMessage, $response->getMessage());
        $this->assertSame($newMessage, $responseBody->message);
    }
}
