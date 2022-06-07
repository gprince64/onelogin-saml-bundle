<?php declare(strict_types=1);
// SPDX-License-Identifier: BSD-3-Clause

namespace Nbgrp\OneloginSamlBundle\DependencyInjection\Security\Factory;

use Nbgrp\OneloginSamlBundle\Event\UserCreatedEvent;
use Nbgrp\OneloginSamlBundle\Event\UserModifiedEvent;
use Nbgrp\OneloginSamlBundle\EventListener\User\UserCreatedListener;
use Nbgrp\OneloginSamlBundle\EventListener\User\UserModifiedListener;
use Nbgrp\OneloginSamlBundle\Security\Http\Authentication\SamlAuthenticationSuccessHandler;
use Nbgrp\OneloginSamlBundle\Security\Http\Authenticator\SamlAuthenticator;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class SamlFactory extends AbstractFactory
{
    public const PRIORITY = -10;

    public function __construct()
    {
        $this->addOption('identifier_attribute');
        $this->addOption('use_attribute_friendly_name', false);
        $this->addOption('user_factory');
        $this->addOption('token_factory');
        $this->addOption('persist_user', false);
        $this->addOption('success_handler', SamlAuthenticationSuccessHandler::class);
    }

    public function getPriority(): int
    {
        return self::PRIORITY;
    }

    public function getKey(): string
    {
        return 'saml';
    }

    /** @psalm-suppress MixedArgument */
    public function createAuthenticator(ContainerBuilder $container, string $firewallName, array $config, string $userProviderId): string
    {
        $authenticatorId = 'security.authenticator.saml.'.$firewallName;
        $authenticator = (new ChildDefinition(SamlAuthenticator::class))
            ->replaceArgument(1, new Reference($userProviderId))
            ->replaceArgument(4, new Reference($this->createAuthenticationSuccessHandler($container, $firewallName, $config)))
            ->replaceArgument(5, new Reference($this->createAuthenticationFailureHandler($container, $firewallName, $config)))
            ->replaceArgument(6, array_intersect_key($config, $this->options))
        ;

        if (!empty($config['user_factory'])) {
            $authenticator->replaceArgument(7, new Reference((string) $config['user_factory']));
        }

        $container->setDefinition($authenticatorId, $authenticator);

        $this->createUserListeners($container, $firewallName, $config);

        return $authenticatorId;
    }

    protected function createUserListeners(ContainerBuilder $container, string $firewallName, array $config): void
    {
        $container->setDefinition('nbgrp_onelogin_saml.user_created_listener.'.$firewallName, new ChildDefinition(UserCreatedListener::class))
            ->replaceArgument(1, $config['persist_user'] ?? false)
            ->addTag('nbgrp.saml_user_listener')
            ->addTag('kernel.event_listener', [
                'event' => UserCreatedEvent::class,
                'dispatcher' => 'security.event_dispatcher.'.$firewallName,
            ])
        ;

        $container->setDefinition('nbgrp_onelogin_saml.user_modified_listener.'.$firewallName, new ChildDefinition(UserModifiedListener::class))
            ->replaceArgument(1, $config['persist_user'] ?? false)
            ->addTag('nbgrp.saml_user_listener')
            ->addTag('kernel.event_listener', [
                'event' => UserModifiedEvent::class,
                'dispatcher' => 'security.event_dispatcher.'.$firewallName,
            ])
        ;
    }

    protected function createAuthProvider(ContainerBuilder $container, string $id, array $config, string $userProviderId): string
    {
        if ($config['enable_csrf'] ?? false) {
            throw new InvalidConfigurationException('The "enable_csrf" option of "form_login" is only available when "security.enable_authenticator_manager" is set to "true", use "csrf_token_generator" instead.');
        }

        $provider = 'security.authentication.provider.dao.'.$id;
        $container
            ->setDefinition($provider, new ChildDefinition('security.authentication.provider.dao'))
            ->replaceArgument(0, new Reference($userProviderId))
            ->replaceArgument(1, new Reference('security.user_checker.'.$id))
            ->replaceArgument(2, $id)
        ;

        return $provider;
    }

    protected function getListenerId(): string
    {
        return 'security.authentication.listener.form';
    }

    public function getPosition(): string
    {
        return 'form';
    }
}
