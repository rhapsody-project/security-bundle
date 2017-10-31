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
namespace Rhapsody\SecurityBundle\Model;

abstract class RefreshToken implements RefreshTokenInterface
{

    /**
     * @var string
     */
    protected $token;

    /**
     * @var \DateTime
     */
    protected $tokenExpired;

    /**
     * @var \DateTime
     */
    protected $tokenExpiresAt;

    /**
     * @var string
     */
    protected $username;

    public function getToken()
    {
        return $this->token;
    }

    public function getTokenExpired()
    {
        return $this->tokenExpired;
    }

    public function getTokenExpiresAt()
    {
        return $this->tokenExpiresAt;
    }

    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Returns whether a refresh token is valid or not.
     * @return boolean
     */
    public function isValid()
    {
        $datetime = new \DateTime;
        return $this->tokenExpiresAt >= $datetime || $this->tokenExpired;
    }

    public function setToken($token)
    {
        $this->token = $token;
        return $this;
    }

    public function setTokenExpired($expired)
    {
        $this->tokenExpired = $tokenExpired;
        return $this;
    }

    public function setTokenExpiresAt(\DateTime $tokenExpiresAt)
    {
        $this->tokenExpiresAt = $tokenExpiresAt;
        return $this;
    }

    public function setUsername($username)
    {
        $this->username = $username;
        return $this;
    }
}