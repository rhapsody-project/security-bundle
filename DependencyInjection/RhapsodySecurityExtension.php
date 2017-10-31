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

use Rhapsody\SecurityBundle\DependencyInjection\Security\Factory\Jwt\JwtClaimsFactory;
use Rhapsody\SecurityBundle\DependencyInjection\Security\Factory\Jwt\JwtTokenExtractorFactory;
use Rhapsody\SecurityBundle\DependencyInjection\Security\SecurityConfigurationFactoryInterface;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\XmlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

/**
 * This is the class that loads and manages your bundle configuration
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html}
 */
class RhapsodySecurityExtension extends Extension
{
    private $jwtSecurityFactories = array();

    public function addJwtSecurityFactory(SecurityConfigurationFactoryInterface $factory)
    {
        $this->jwtSecurityFactories[] = $factory;
    }

    /**
     * {@inheritDoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
    	$loader = new XmlFileLoader($container, new FileLocator(dirname(__DIR__).'/Resources/config'));
    	$loader->load('security_listeners.xml');
    	$loader->load('security_rememberme.xml');

        $configuration = $this->getConfiguration($configs, $container);
        $config = $this->processConfiguration($configuration, $configs);

    	$container->setParameter('rhapsody_security.storage', $config['db_driver']);

    	if ('custom' !== $config['db_driver']) {
    		$loader->load(sprintf('%s.xml', $config['db_driver']));
    	}

    	// TODO: $this->registerSecurityAclConfiguration($config['acl'], $container, $loader);
    	$this->registerSecurityJwtConfiguration($config['jwt'], $container, $loader);
    }

    public function getAlias()
    {
    	return 'rhapsody_security';
    }

    /**
     * Returns the namespace to be used for this extension (XML namespace).
     *
     * @return string The XML namespace
     */
    public function getNamespace()
    {
    	return 'http://symfony.com/schema/dic/rhapsody/security';
    }

    protected function getObjectManagerElementName($name)
    {
    	return 'doctrine_mongodb.odm.' . $name;
    }

    protected function getMappingObjectDefaultName()
    {
    	return 'Document';
    }

    protected function getMappingResourceConfigDirectory()
    {
    	return 'Resources/config/doctrine';
    }

    protected function getMappingResourceExtension()
    {
    	return 'mongodb';
    }

    /**
     * Loads the ACL security configuration.
     *
     * @param array $config An ACL configuration array
     * @param ContainerBuilder $container A ContainerBuilder instance
     * @param XmlFileLoader $loader An XmlFileLoader instance
     *
     * @throws \LogicException
     */
    private function registerSecurityAclConfiguration($config, ContainerBuilder $container, LoaderInterface $loader)
    {
        if (!$this->isConfigEnabled($container, $config)) {
            return;
        }

        //if (isset($config['acl_provider']) && isset($config['acl_provider']['default_database'])) {
        //    $this->loadAcl($config['acl_provider'], $container);
        //    ... do either the above or the below... not both!!
        //    $container->setParameter('doctrine_mongodb.odm.security.acl.database', $config['acl_provider']['default_database']);
    	//    $container->setParameter('doctrine_mongodb.odm.security.acl.entry_collection', $config['acl_provider']['collections']['entry']);
    	//    $container->setParameter('doctrine_mongodb.odm.security.acl.oid_collection', $config['acl_provider']['collections']['object_identity']);
        //}
        $loader->load('security_acl.xml');
    }

    /**
     * Loads the JSON Web Token security configuration.
     *
     * @param array $config A JSON Web Token configuration array
     * @param ContainerBuilder $container A ContainerBuilder instance
     * @param XmlFileLoader $loader An XmlFileLoader instance
     *
     * @throws \LogicException
     */
    private function registerSecurityJwtConfiguration($config, ContainerBuilder $container, LoaderInterface $loader)
    {
        if (!$this->isConfigEnabled($container, $config)) {
            return;
        }

        // Global JWT parameters.
        $container->setParameter('rhapsody_security.jwt.private_key_path', $config['private_key_path']);
        $container->setParameter('rhapsody_security.jwt.public_key_path', $config['public_key_path']);
        $container->setParameter('rhapsody_security.jwt.pass_phrase', $config['pass_phrase']);
        $container->setParameter('rhapsody_security.jwt.token_ttl', $config['token_ttl']);

        // Encoder parameters.
        $cryptoEngine = $config['encoder']['crypto_engine'];
        $container->setParameter('rhapsody_security.jwt.encoder.crypto_engine', $cryptoEngine);
        $container->setParameter('rhapsody_security.jwt.encoder.signature_algorithm', $config['encoder']['signature_algorithm']);

        $container->setAlias('rhapsody_security.jwt_encoder', $config['encoder']['service']);
        $container->setAlias(
            'rhapsody_security.jwt_key_loader',
            'rhapsody_security.jwt.key_loader.'.('openssl' === $cryptoEngine ? $cryptoEngine : 'raw'));
        $container->setAlias('rhapsody_security.jwt_payload_adapter', $config['payload']['adapter']);
        $loader->load('security_jwt.xml');

        $container->getDefinition('rhapsody_security.jwt_manager')
            ->addMethodCall('setIdentityClaim', array($config['payload']['identity_claim']));

        $factory = new JwtClaimsFactory();
        $factory->create($container, $config['payload']);

        $factory = new JwtTokenExtractorFactory();
        $factory->create($container, $config['token_extractors']);
    }
}
