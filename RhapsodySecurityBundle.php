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
namespace Rhapsody\SecurityBundle;

use Rhapsody\SecurityBundle\DependencyInjection\Security\Factory\JwtLoginFactory;
use Rhapsody\SecurityBundle\DependencyInjection\Security\Factory\JwtRefreshFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 *
 * @author    Sean W. Quinn <sean.quinn@extesla.com>
 * @category  Rhapsody SecurityBundle
 * @package   Rhapsody\SecurityBundle
 * @copyright Rhapsody Project
 * @version   $Id$
 * @since     1.0
 */
class RhapsodySecurityBundle extends Bundle
{
    /**
     * {@inheritDoc}
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        // **
        // NB: Load the core Symfony Framework security extension and add the
        //     Rhapsody Security security listener factories to it for
        //     creation. [SWQ]
        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new JwtLoginFactory());
        $extension->addSecurityListenerFactory(new JwtRefreshFactory());

        // TODO: Support better compartmentalized JWT security factories...
        //$extension->addJwtSecurityFactory(new JwtPayloadAdapterFactory());
        //$extension->addJwtSecurityFactory(new JwtEncoderFactory());
        //$extension->addJwtSecurityFactory(new JwtClaimsFactory());
    }
}
