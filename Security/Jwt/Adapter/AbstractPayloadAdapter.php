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
namespace Rhapsody\SecurityBundle\Security\Jwt\Adapter;

use Monolog\Logger;
use Psr\Log\LoggerInterface;
use Rhapsody\SecurityBundle\Security\Jwt\ClaimInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 *
 * @author    Sean W. Quinn <sean.quinn@extesla.com>
 * @category  Rhapsody SecurityBundle
 * @package   Rhapsody\SecurityBundle\Security\Jwt\Adapter
 * @copyright Rhapsody Project
 * @version   $Id$
 * @since     1.0
 */
abstract class AbstractPayloadAdapter implements PayloadAdapterInterface
{

    /**
     * @var \Psr\Log\LoggerInterface
     */
    protected $logger;

    public function _construct(LoggerInterface $logger = null)
    {
        $this->logger = $logger;
    }

    /**
     * Adds the <code>property</code> associated with the <code>$claim</code> to
     * the <code>$payload</code>.
     *
     * If a <code>$claim</code> is required and the property resolves to an
     * empty value, an <code>UnexpectedValueException</code> will be raised.
     *
     * @param UserInterface $user The user.
     * @param ClaimInterface $claim The claim being added to the payload.
     * @param array $payload The payload having the claim set.
     * @throws \UnexpectedValueException
     */
    abstract protected function addUserClaimToPayload(UserInterface $user, ClaimInterface $claim, array &$payload);

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\Adapter\PayloadAdapterInterface::createPayload()
     */
    public function createPayload(UserInterface $user, array $claims = array())
    {
        $payload = array();
        foreach ($claims as $claim) {
            $this->addUserClaimToPayload($user, $claim, $payload);
        }
        return $payload;
    }
}
