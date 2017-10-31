<?php
/* Copyright (c) 2013 Rhapsody Project
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
namespace Rhapsody\SecurityBundle\Doctrine;

use Doctrine\Common\Persistence\ObjectManager;
use Rhapsody\SecurityBundle\Model\RefreshTokenInterface;
use Rhapsody\SecurityBundle\Service\RefreshTokenManager as BaseRefreshTokenManager;

/**
 *
 * @author    Sean W. Quinn <sean.quinn@extesla.com>
 * @category  Rhapsody SecurityBundle
 * @package   Rhapsody\SecurityBundle\Doctrine
 * @copyright Rhapsody Project
 * @version   $Id$
 * @since     1.0
 */
class RefreshTokenManager extends BaseRefreshTokenManager
{

    protected $objectManager;
    protected $class;

    public function __construct(ObjectManager $objectManager, $class)
    {
        $this->objectManager = $objectManager;
        $this->repository = $objectManager->getRepository($class);
        $metadata = $om->getClassMetadata($class);
        $this->class = $metadata->getName();
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Service\RefreshTokenManagerInterface::revoke()
     */
    public function revoke(RefreshTokenInterface $refreshToken, $andFlush = true)
    {
        throw new \Exception('Not yet implemented');
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Service\RefreshTokenManagerInterface::revokeAllInvalid()
     */
    public function revokeAllInvalid($dateTime = null, $andFlush = true)
    {
        throw new \Exception('Not yet implemented');
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Service\RefreshTokenManagerInterface::save()
     */
    public function save(RefreshTokenInterface $refreshToken, $andFlush = true)
    {
        throw new \Exception('Not yet implemented');
    }

}