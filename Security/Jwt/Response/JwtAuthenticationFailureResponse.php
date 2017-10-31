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
namespace Rhapsody\SecurityBundle\Security\Jwt\Response;

use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * JWTAuthenticationFailureResponse.
 *
 * Response sent on failed JWT authentication (can be replaced by a custom Response).
 *
 * @internal
 *
 * @author Robin Chalas <robin.chalas@gmail.com>
 */
final class JwtAuthenticationFailureResponse extends JsonResponse
{
    /**
     * The response message.
     *
     * @var string
     */
    private $message;

    /**
     * @param string $message A failure message passed in the response body
     */
    public function __construct($message = 'Bad credentials', $statusCode = JsonResponse::HTTP_UNAUTHORIZED)
    {
        $this->message = $message;
        parent::__construct(null, $statusCode, ['WWW-Authenticate' => 'Bearer']);
    }

    /**
     * Sets the failure message.
     *
     * @param string $message
     *
     * @return JWTAuthenticationFailureResponse
     */
    public function setMessage($message)
    {
        $this->message = $message;
        $this->setData();
        return $this;
    }

    /**
     * Gets the failure message.
     *
     * @return string
     */
    public function getMessage()
    {
        return $this->message;
    }

    /**
     * Sets the response data with the statusCode & message included.
     *
     * {@inheritdoc}
     */
    public function setData($data = [])
    {
        parent::setData((array) $data + ['code' => $this->statusCode, 'message' => $this->message]);
    }
}
