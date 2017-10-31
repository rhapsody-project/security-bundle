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
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Token\JsonWebToken;
use Rhapsody\SecurityBundle\Security\Jwt\Response\JwtAuthenticationSuccessResponse;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 */
final class JwtAuthenticationSuccessResponseTest extends TestCase
{
    public function testResponse()
    {
        $data = array(
            'username' => 'jameskirk',
            'email'    => 'jameskirk@enterprise.starfleet.fed',
        );
        $expected = array('token' => 'jwt') + $data;

        $jwt = new JsonWebToken($this->createMock(UserInterface::class), 'jwt');
        $jwt->setPayload($data);

        $response = new JwtAuthenticationSuccessResponse($jwt, $data);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(json_encode($expected), $response->getContent());
        return $response;
    }

    /**
     * @depends testResponse
     */
    public function testReplaceData(JwtAuthenticationSuccessResponse $response)
    {
        $replacementData = ['foo' => 'bar'];
        $response->setData($replacementData);

        // Test that the previous method call has no effect on the original body
        $this->assertNotEquals(json_encode($replacementData), $response->getContent());
        $this->assertAttributeSame($replacementData['foo'], 'foo', json_decode($response->getContent()));
        $this->assertAttributeNotEmpty('token', json_decode($response->getContent()));
    }
}
