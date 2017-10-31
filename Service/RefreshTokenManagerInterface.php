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
namespace Rhapsody\SecurityBundle\Service;

use Rhapsody\SecurityBundle\Model\RefreshTokenInterface;

/**
 *
 * @author    Sean W. Quinn <sean.quinn@extesla.com>
 * @category  Rhapsody SecurityBundle
 * @package   Rhapsody\SecurityBundle\Service
 * @copyright Rhapsody Project
 * @version   $Id$
 * @since     1.0
 */
interface RefreshTokenManagerInterface
{

    /**
     * Revokes a refresh token by deleting it from the storage backend.
     *
     * @param RefreshTokenInterface $refreshToken
     * @param bool $andFlush
     */
    function revoke(RefreshTokenInterface $refreshToken, $andFlush = true);

    /**
     * Finds and revokes all refresh tokens that are invalid, given the passed
     * <code>$dateTime</code>. If <code>$dateTime</code> is <code>null</code>
     * all refresh tokens will be revoked.
     *
     * @param \DateTime $dateTime
     * @param bool $andFlush
     * @return RefreshTokenInterface[] The invalid tokens.
     */
    function revokeAllInvalid($dateTime = null, $andFlush = true);

    /**
     *
     * @param RefreshTokenInterface $refreshToken
     * @param bool $andFlush
     */
    function save(RefreshTokenInterface $refreshToken, $andFlush = true);
}