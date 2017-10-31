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
namespace Rhapsody\SecurityBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * <p>
 * </p>
 *
 * @author    Sean W. Quinn <sean.quinn@extesla.com>
 * @category  Rhapsody SecurityBundle
 * @package   Rhapsody\SecurityBundle\DependencyInjection
 * @copyright Copyright (c) 2013 Rhapsody Project
 * @version   $Id$
 * @since     1.0
 */
class Configuration implements ConfigurationInterface
{

    /**
     *
     * @param ArrayNodeDefinition $rootNode
     */
    private function addJwtSection(ArrayNodeDefinition $rootNode)
    {
        $defaultTokenTtl = 3600;

        $rootNode
            ->children()
                ->arrayNode('jwt')
                    ->treatFalseLike(array('enabled' => false))
                    ->treatTrueLike(array('enabled' => true))
                    ->treatNullLike(array('enabled' => true))
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')->defaultNull()->end()
                        ->scalarNode('private_key_path')
                            ->defaultNull()
                        ->end()
                        ->scalarNode('public_key_path')
                            ->defaultNull()
                        ->end()
                        ->scalarNode('pass_phrase')
                            ->defaultNull()
                        ->end()
                        ->scalarNode('token_ttl')
                            ->treatNullLike($defaultTokenTtl)
                            ->defaultValue($defaultTokenTtl)
                            ->validate()
                                ->ifTrue(function ($ttl) {
                                    return !is_numeric($ttl);
                                })
                                ->thenInvalid('The token_ttl must be a numeric value.')
                            ->end()
                        ->end()
                        ->append($this->getJwtPayloadNode())
                        ->append($this->getJwtEncoderNode())
                        ->append($this->getJwtTokenExtractorNode())
                    ->end()
                ->end()
            ->end()
        ;
    }

    private function getSupportedDatabaseDrivers()
    {
        //return array('orm', 'mongodb', 'couchdb', 'propel', 'custom');
        return array('orm', 'mongodb', 'custom');
    }

    /**
     * Generates the configuration tree builder.
     *
     * @return \Symfony\Component\Config\Definition\Builder\TreeBuilder The tree builder
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('rhapsody_security');

        $supportedDrivers = $this->getSupportedDatabaseDrivers();
        $rootNode
            ->children()
                ->scalarNode('db_driver')
                    ->validate()
                        ->ifNotInArray($supportedDrivers)
                        ->thenInvalid('The driver %s is not supported. Please choose one of '.json_encode($supportedDrivers))
                    ->end()
                    ->cannotBeOverwritten()
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
            ->end()
        ;


        // ** Add additional sections to the configuration...
        $this->addJwtSection($rootNode);

        return $treeBuilder;
    }

    /**
     *
     * @return \Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition|\Symfony\Component\Config\Definition\Builder\NodeDefinition
     */
    private function getJwtEncoderNode()
    {
        $builder = new TreeBuilder();
        $node = $builder->root('encoder');

        $defaultEncoder = 'rhapsody_security.jwt.encoder.default';
        $defaultCryptoEngine = 'openssl';
        $defaultSignatureAlgorithm = 'RS256';

        $node
            ->addDefaultsIfNotSet()
            ->children()
                ->scalarNode('service')
                    ->defaultValue($defaultEncoder)
                ->end()
                ->scalarNode('signature_algorithm')
                    ->defaultValue($defaultSignatureAlgorithm)
                    ->cannotBeEmpty()
                ->end()
                ->enumNode('crypto_engine')
                    ->defaultValue($defaultCryptoEngine)
                    ->values(['openssl', 'phpseclib'])
                ->end()
            ->end()
        ;
        return $node;
    }

    /**
     *
     * @return \Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition|\Symfony\Component\Config\Definition\Builder\NodeDefinition
     */
    private function getJwtPayloadNode()
    {
        $builder = new TreeBuilder();
        $node = $builder->root('payload');

        $defaultAdapter = 'rhapsody_security.jwt.adapter.payload_adapter.default';
        $defaultIdentityClaim = 'identity';

        $node
            ->fixXmlConfig('claim')
            ->addDefaultsIfNotSet()
            ->children()
                ->scalarNode('adapter')
                    ->defaultValue($defaultAdapter)
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('identity_claim')
                    ->defaultValue($defaultIdentityClaim)
                    ->cannotBeEmpty()
                ->end()
                ->arrayNode('claims')
                    ->example(array(
                        'my_optional_claim' => array('name' => 'foo', 'property' => 'bar', 'required' => false),
                        'my_required_claim' => array('name' => 'bar', 'property' => 'baz', 'required' => true)
                      ))
                    ->requiresAtLeastOneElement()
                    ->useAttributeAsKey('id')
                    ->prototype('array')
                    ->children()
                        ->scalarNode('name')->isRequired()->end()
                        ->scalarNode('property')->end()
                        ->scalarNode('required')->defaultFalse()->end()
                    ->end()
                ->end()
            ->end()
        ;
        return $node;
    }

    /**
     *
     * @return \Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition|\Symfony\Component\Config\Definition\Builder\NodeDefinition
     */
    private function getJwtTokenExtractorNode()
    {
        $builder = new TreeBuilder();
        $node = $builder->root('token_extractors');

        $node
            ->addDefaultsIfNotSet()
            ->children()
                ->arrayNode('authorization_header')
                    ->addDefaultsIfNotSet()
                    ->canBeDisabled()
                    ->children()
                        ->scalarNode('prefix')
                            ->defaultValue('Bearer')
                        ->end()
                        ->scalarNode('name')
                            ->defaultValue('Authorization')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('cookie')
                    ->addDefaultsIfNotSet()
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('name')
                            ->defaultValue('BEARER')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('json_body')
                    ->addDefaultsIfNotSet()
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('name')
                            ->defaultValue('token')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('query_parameter')
                    ->addDefaultsIfNotSet()
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('name')
                            ->defaultValue('bearer')
                        ->end()
                    ->end()
                ->end()
            ->end()
        ;
        return $node;
    }
}
