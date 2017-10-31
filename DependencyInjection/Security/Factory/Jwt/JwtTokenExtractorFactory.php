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

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 */
class JwtTokenExtractorFactory implements JwtSecurityFactoryInterface
{

    public function create(ContainerBuilder $container, array $config)
    {
        $container
            ->getDefinition('rhapsody_security.jwt.token_extractor.chain_token_extractor')
            ->replaceArgument(0, $this->createTokenExtractors($container, $config));
    }

    public function getKey()
    {
        return 'token_extractors';
    }

    private function createTokenExtractors(ContainerBuilder $container, array $config)
    {
        $map = array();

        if ($this->isTokenExtractorEnabled('authorization_header', $config)) {
            $authorizationHeaderExtractorId = 'rhapsody_security.jwt.token_extractor.authorization_header_token_extractor';
            $container->getDefinition($authorizationHeaderExtractorId)
                ->replaceArgument(0, $config['authorization_header']['prefix'])
                ->replaceArgument(1, $config['authorization_header']['name']);

            array_push($map, new Reference($authorizationHeaderExtractorId));
        }

        if ($this->isTokenExtractorEnabled('json_body', $config)) {
            $jsonBodyExtractorId = 'rhapsody_security.jwt.token_extractor.json_body_token_extractor';
            $container->getDefinition($jsonBodyExtractorId)
                ->replaceArgument(0, $config['json_body']['name']);

            array_push($map, new Reference($jsonBodyExtractorId));
        }

        if ($this->isTokenExtractorEnabled('query_parameter', $config)) {
            $queryParameterExtractorId = 'rhapsody_security.jwt.token_extractor.query_parameter_token_extractor';
            $container->getDefinition($queryParameterExtractorId)
                ->replaceArgument(0, $config['query_parameter']['name']);

            array_push($map, new Reference($queryParameterExtractorId));
        }

        if ($this->isTokenExtractorEnabled('cookie', $config)) {
            $cookieExtractorId = 'rhapsody_security.jwt.token_extractor.cookie_token_extractor';
            $container->getDefinition($cookieExtractorId)
                ->replaceArgument(0, $config['cookie']['name']);

            array_push($map, new Reference($cookieExtractorId));
        }

        return $map;
    }

    /**
     *
     * @param unknown $tokenExtractor
     * @param unknown $config
     * @return boolean
     */
    private function isTokenExtractorEnabled($key, $config)
    {
        if (!isset($config[$key])) {
            return false;
        }

        $tokenExtractorConfig = $config[$key];
        if (isset($tokenExtractorConfig['enabled']) && $tokenExtractorConfig['enabled']) {
            return true;
        }
        return false;
    }
}
