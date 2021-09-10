<?php

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Bundle\FrameworkBundle\DependencyInjection\Configuration;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

class ConductionSamlBundleExtension extends Extension implements PrependExtensionInterface
{

    public function load(array $configs, ContainerBuilder $container)
    {
        $loader = new XmlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.xml');
        $loader->load('routes.xml');
    }

    public function prepend(ContainerBuilder $container)
    {
        $configs = $container->getExtensionConfig($this->getAlias());

        $resolvingBag = $container->getParameterbag();
        $configs = $resolvingBag->resolveValue($configs);

        $config = $this->processConfiguration(new Configuration(), $configs);
        $config = $this->getDefaultConfig();
        $container->prependExtensionConfig('conduction_saml', $config);

        $container->setParameter('conduction_saml.settings', $config);

        $parameters = $this->getDefaultParameters();
        $container->prependExtensionConfig('parameters', $parameters);
    }

    public function getDefaultSp(): array
    {
        return [
            'entityId'                  => '%env(APP_URL)%/saml',
            'assertionConsumerService'  => [
                'url'       => '%env(APP_URL)%/saml/SLO/artifact',
                'binding'   => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact',
            ],
            'singleLogoutService'       => [
                'url'       => '%env(APP_URL)%/saml/logout',
                'binding'   => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            ],
            'privateKey'                => '%env(file:APP_KEY)%',
            'x509cert'                  => '%env(file:APP_CERT)%',
        ];
    }
    public function getDefaultIdp(): array
    {
        return [
            'entityId'                  => '%env(SAML_METADATA_LOCATION)%',
            'singleSignOnService'  => [
                'url'       => '%env(SAML_SIGN_ON_URL)%',
                'binding'   => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            ],
            'singleLogoutService'       => [
                'url'       => '%env(SAML_LOGOUT_URL)%',
                'binding'   =>  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            ],
            'x509cert'                  => '%env(file:SAML_IDP_CERT)%',
        ];
    }

    public function getDefaultSecurity(): array
    {
        return [
            'nameIdEncrypted'       => false,
            'authnRequestsSigned'   => true,
            'logoutRequestSigned'   => false,
            'logoutResponseSigned'  => false,
            'wantMessageSigned'     => false,
            'wantAssertionSigned'   => false,
            'wantNameIdEncrypted'   => false,
            'requestAuthnContext'   => [
                'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
            ],
            'signMetadata'          => true,
            'wantXMLValidation'     => true,
            'signatureAlgorithm'    => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'digestAlgorithm'       => 'http://www.w3.org/2001/04/xmlenc#sha256'
        ];
    }

    public function getDefaultConfig(): array
    {
        return [
            'strict'    => 'true',
            'debug'     => 'false',
            'baseUrl'   => '%env(APP_URL)%',
            'sp'        => $this->getDefaultSp(),
            'idp'       => $this->getDefaultIdp(),
            'security'  => $this->getDefaultSecurity(),
        ];
    }

    public function getDefaultParameters(): array
    {
        return [
            'app_cert'                      => '%env(APP_CERT)%',
            'app_key'                       => '%env(APP_KEY)%',
            'app_x509_cert'                 => '%env(file:APP_CERT)%',
            'env(SAML_METADATA_LOCATION)'   => 'https://example.com/saml/metadata',
            'env(SAML_SIGN_ON_URL)'         => 'https://example.com/saml2',
            'env(SAML_LOGOUT_URL)'          => 'https://example.com/saml2',
            'env(SAML_IDP_CERT)'            => '/var/certs/idp.crt',
            'env(APP_CERT)'                 => '/var/certs/certificate.crt',
            'env(APP_KEY)'                  => '/var/certs/certificate.key',
        ];
    }
}