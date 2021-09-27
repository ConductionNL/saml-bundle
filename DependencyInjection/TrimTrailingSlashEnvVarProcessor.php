<?php

namespace Conduction\SamlBundle\DependencyInjection;

class TrimTrailingSlashEnvVarProcessor implements \Symfony\Component\DependencyInjection\EnvVarProcessorInterface
{
    public function getEnv(string $prefix, string $name, \Closure $getEnv)
    {
        $env = $getEnv($name);

        return rtrim($env, '/');
    }

    public static function getProvidedTypes()
    {
        return [
            'trimtrailingslash' => 'string',
        ];
    }
}