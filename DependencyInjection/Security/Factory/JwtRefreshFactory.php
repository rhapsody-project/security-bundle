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
namespace Rhapsody\SecurityBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * The <code>JwtRefreshFactory</code> creates services that allow "Remember Me"
 * like functionality for JSON Web Tokens (JWTs).
 *
 * @author    Sean W. Quinn <sean.quinn@extesla.com>
 * @category  Rhapsody SecurityBundle
 * @package   Rhapsody\SecurityBundle\DependencyInjection\Security\Factory
 * @copyright Rhapsody Project
 * @version   $Id$
 * @since     1.0
 */
class JwtRefreshFactory implements SecurityFactoryInterface
{
    use \Rhapsody\SecurityBundle\Traits\ChildDefinitionCompatibleTrait;

    protected $defaultFailureHandlerOptions = array();
    protected $defaultSuccessHandlerOptions = array();
    protected $options = array(
        'path' => '/token_refresh',
        //'secure' => false,
        //'httponly' => true,
        //'always_remember_me' => false,
        //'remember_me_parameter' => '_remember_me',
    );

    public function addConfiguration(NodeDefinition $node)
    {
        $builder = $node->fixXmlConfig('user_provider')->children();

        $builder
            ->scalarNode('provider')->end()
            // TODO: Multiple providers not currently supported.
            // ->arrayNode('user_providers')
            //     ->beforeNormalization()
            //         ->ifString()->then(function ($v) { return array($v); })
            //     ->end()
            //     ->prototype('scalar')->end()
            // ->end()
            ->scalarNode('success_handler')->end()
            ->scalarNode('failure_handler')->end()
            ->scalarNode('catch_exceptions')->defaultTrue()->end()
        ;

        $options = array_merge($this->options, $this->defaultSuccessHandlerOptions, $this->defaultFailureHandlerOptions);
        foreach ($options as $name => $default) {
            if (is_bool($default)) {
                $builder->booleanNode($name)->defaultValue($default);
            } else {
                $builder->scalarNode($name)->defaultValue($default);
            }
        }
    }

    public function create(ContainerBuilder $container, $id, $config, $userProviderId, $defaultEntryPointId)
    {
        // authentication provider
        $authProviderId = $this->createAuthProvider($container, $id, $config, $userProviderId);

        // authentication listener
        $listenerId = $this->createListener($container, $id, $config, $userProviderId);

        return array($authProviderId, $listenerId, $defaultEntryPointId);
    }

    protected function createAuthenticationFailureHandler($container, $id, $config)
    {
        $id = $this->getFailureHandlerId($id);
        $options = array_intersect_key($config, $this->defaultFailureHandlerOptions);

        if (isset($config['failure_handler'])) {
            $failureHandler = $container->setDefinition($id, $this->newChildDefinition('security.authentication.custom_failure_handler'));
            $failureHandler->replaceArgument(0, new Reference($config['failure_handler']));
            $failureHandler->replaceArgument(1, $options);
        } else {
            $failureHandler = $container->setDefinition($id, $this->newChildDefinition('security.authentication.failure_handler'));
            $failureHandler->addMethodCall('setOptions', array($options));
        }

        return $id;
    }

    protected function createAuthenticationSuccessHandler($container, $id, $config)
    {
        $successHandlerId = $this->getSuccessHandlerId($id);
        $options = array_intersect_key($config, $this->defaultSuccessHandlerOptions);

        if (isset($config['success_handler'])) {
            $successHandler = $container->setDefinition($successHandlerId, $this->newChildDefinition('security.authentication.custom_success_handler'));
            $successHandler->replaceArgument(0, new Reference($config['success_handler']));
            $successHandler->replaceArgument(1, $options);
            $successHandler->replaceArgument(2, $id);
        } else {
            $successHandler = $container->setDefinition($successHandlerId, $this->newChildDefinition('security.authentication.success_handler'));
            $successHandler->addMethodCall('setOptions', array($options));
            $successHandler->addMethodCall('setProviderKey', array($id));
        }

        return $successHandlerId;
    }

    protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
    {
        $authenticationProviderId = 'rhapsody_security.authentication.provider.jwt.'.$id;
        $container
            ->setDefinition($authenticationProviderId, $this->newChildDefinition('rhapsody_security.authentication.provider.jwt'))
            ->replaceArgument(0, new Reference($userProviderId))
            ->replaceArgument(1, new Reference('security.user_checker.'.$id))
            ->replaceArgument(2, $id)
        ;

        // TODO: Support multiple user providers
        // ** Derive the collection of remember-me aware user providers
        // $userProviders = $this->createUserProviders($container, $id, $config, $rememberMeServicesId);

        return $authenticationProviderId;
    }

    protected function createListener(ContainerBuilder $container, $id, $config, $userProviderId)
    {
        // ** JWT Remember Me Listener
        $listenerTemplateId = 'rhapsody_security.authentication.listener.jwt_refresh';

        $listener = $this->newChildDefinition($listenerTemplateId);
        $listener->replaceArgument(0, new Reference($this->createRememberMeServicesId($container, $id, $userProviderId)));
        $listener->replaceArgument(3, $id);
        $listener->replaceArgument(4, new Reference($this->createAuthenticationSuccessHandler($container, $id, $config)));
        $listener->replaceArgument(5, new Reference($this->createAuthenticationFailureHandler($container, $id, $config)));
        $listener->replaceArgument(6, array_intersect_key($config, $this->options));
        //TODO: Set "catch_exceptions" on listener to prevent exceptions from leaking?

        $listenerId = 'rhapsody_security.authentication.listener.jwt_refresh.'.$id;
        $container->setDefinition($listenerId, $listener);

        return $listenerId;
    }

    /**
     * Creates a definition for the remember me services that will be associated
     * with the refresh services.
     *
     * @param ContainerBuilder $container
     * @param string $id The provider key.
     * @param string $userProviderId The user provider ID.
     */
    protected function createRememberMeServicesId(ContainerBuilder $container, $id, $userProviderId)
    {
        // TODO: We only support simple JWT refreshes currently; in the future
        //       we will likely want to support persistent refresh tokens and
        //       other types of remember me services. In those cases we will
        //       have to resolve the template ID differently.
        $rememberMeServicesTemplateId = 'rhapsody_security.jwt.authentication.rememberme.services.simple_jwt';
        $rememberMeServicesId = sprintf('%s.%s', $rememberMeServicesTemplateId, $id);

        // ** JWT Remember Me Services
        $container
            ->setDefinition($rememberMeServicesId, $this->newChildDefinition($rememberMeServicesTemplateId))
            ->replaceArgument(0, new Reference($userProviderId))
            ->replaceArgument(3, $id)
        ;

        return $rememberMeServicesId;
    }

    /**
     * Creates a collection of references to user providers for all services
     * tagged with <code>security.remember_me_aware</code>
     */
    protected function createUserProviders(ContainerBuilder $container, $id, $config, $rememberMeServicesId)
    {
        $userProviders = array();

        // **
        // NB: When a firewall, e.g. jwt_login, is marked as supporting remember
        //     me functionality, it will be tagged as remember-me aware (i.e.
        //     "security.remember_me_aware"). This iterates over all of the
        //     user providers associated with those services extracts the IDs
        //     creating an array of references.
        //
        //     Most of this is obvious is you look through the source code and
        //     may even be covered in some of the documentation. However, it was
        //     not immediately evident to me how all of this fit together, hence
        //     the note here. [SWQ]
        foreach ($container->findTaggedServiceIds('security.remember_me_aware') as $serviceId => $attributes) {
            foreach ($attributes as $attribute) {
                if (!isset($attribute['id']) || $attribute['id'] !== $id) {
                    continue;
                }

                if (!isset($attribute['provider'])) {
                    throw new \RuntimeException('Each "security.remember_me_aware" tag must have a provider attribute.');
                }

                $userProviders[] = new Reference($attribute['provider']);
                $container
                    ->getDefinition($serviceId)
                    ->addMethodCall('setRememberMeServices', array(new Reference($rememberMeServicesId)));
            }
        }

        if ($config['user_providers']) {
            $userProviders = array();
            foreach ($config['user_providers'] as $providerName) {
                $userProviders[] = new Reference(sprintf('security.user.provider.concrete.%s', $providerName));
            }
        }

        if (count($userProviders) === 0) {
            throw new \RuntimeException('You must configure at least one remember-me aware listener (such as jwt-login) for each firewall that has remember-me enabled.');
        }
        return $userProviders;
    }

    protected function getSuccessHandlerId($id)
    {
        return sprintf('rhapsody_security.authentication.success_handler.%s.%s', $id, str_replace('-', '_', $this->getKey()));
    }

    protected function getFailureHandlerId($id)
    {
        return sprintf('rhapsody_security.authentication.failure_handler.%s.%s', $id, str_replace('-', '_', $this->getKey()));
    }

    /**
     * {@inheritdoc}
     */
    public function getPosition()
    {
        return 'remember_me';
    }

    /**
     * {@inheritdoc}
     */
    public function getKey()
    {
        return 'jwt-refresh';
    }

}
