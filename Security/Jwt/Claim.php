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
namespace Rhapsody\SecurityBundle\Security\Jwt;

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
final class Claim implements ClaimInterface
{

    /**
     * The name of the claim, this is the <code>key</code> that defines a
     * claim's entry in the JWT payload.
     *
     * @var string
     */
    private $name;

    /**
     * The property to look up a claim's value on an object that implements the
     * <code>UserInterface</code>.
     *
     * @var string
     */
    private $property;

    /**
     * Whether the claim is required or not. Not all claims need to be on a
     * JWT for us to consider it valid, in fact aside from claims like
     * <code>exp</code>, <code>iat</code>, etc. most of the claims represented
     * by this class are "optional".
     *
     * @var bool
     */
    private $required;

    public function __construct($name, $property, $required = false)
    {
        // **
        // By default if a property value hasn't been supplied we'll assume the
        // the $name and $property should be the same. [SWQ]
        if (empty($property)) {
            $property = $name;
        }

        $this->name = $name;
        $this->property = $property;
        $this->required = $required;
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\Adapter\ClaimInterface::getName()
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\Adapter\ClaimInterface::getProperty()
     */
    public function getProperty()
    {
        return $this->property;
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\Adapter\ClaimInterface::isRequired()
     */
    public function isRequired()
    {
        return $this->required;
    }
}