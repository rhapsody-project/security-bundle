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
namespace Rhapsody\SecurityBundle\DependencyInjection\Security\Factory\Jwt;

use Rhapsody\SecurityBundle\Security\Jwt\Adapter\Claim;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 */
class JwtClaimsFactory implements JwtSecurityFactoryInterface
{
    use \Rhapsody\SecurityBundle\Traits\ChildDefinitionCompatibleTrait;

    public function create(ContainerBuilder $container, array $config)
    {
        $prototypeId = 'rhapsody_security.jwt.claims.claim';
        $definition = $container->getDefinition('rhapsody_security.jwt_manager');

        foreach ($config['claims'] as $id => $claim) {
            $claimId = $prototypeId.'_'.$id;

            $name = $claim['name'];
            $property = $this->getValue($claim, 'property', null);
            $required = $this->getValue($claim, 'required', false);

            $container
                ->setDefinition($claimId, $this->newChildDefinition('rhapsody_security.jwt.claim'))
                ->setArguments(array($name, $property, $required))
            ;
            $definition->addMethodCall('addClaim', array($id, new Reference($claimId)));
        }
    }



    public function getKey()
    {
        return 'claims';
    }

    private function getValue($array, $key, $default)
    {
        return isset($array[$key]) ? $array[$key] : $default;
    }
}
