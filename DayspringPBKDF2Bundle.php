<?php

namespace Dayspring\PBKDF2Bundle;

use Dayspring\PBKDF2Bundle\DependencyInjection\Security\Factory\PBKDF2Factory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class DayspringPBKDF2Bundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new PBKDF2Factory());
    }
}
