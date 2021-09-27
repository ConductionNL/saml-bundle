<?php


namespace Conduction\SamlBundle\Service;

use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

class SamlService
{
    private ParameterBagInterface $parameterBag;

    public function __construct(ParameterBagInterface $parameterBag)
    {
        $this->parameterBag = $parameterBag;
    }

    public function checkSamlEnabled(): bool
    {
        if(!$this->parameterBag->get('saml_enabled')){
            throw new HttpException(416, 'There is no SAML connection enabled');
        } else {
            return true;
        }
    }

    public function getDigestMethod(): array
    {
        return [
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmlenc#sha512',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2009/xmlenc11#aes192-gcm',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmlenc#sha256',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#sha224',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2000/09/xmldsig#sha1',
            ],
        ];
    }

    public function getSigningMethod(): array
    {
        return [
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2009/xmldsig11#dsa-sha256',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2000/09/xmldsig#dsa-sha1',
            ],
        ];
    }
    public function getExtensions(): array
    {
        return [
            '@xmlns:alg' => 'urn:oasis:names:tc:SAML:metadata:algsupport',
            'alg:DigestMethod' => $this->getDigestMethod(),
            'alg:SigningMethod' => $this->getSigningMethod(),
        ];
    }

    public function getSPSSODescriptor(): array
    {
        return [
            '@AuthnRequestsSigned' => '1',
            '@protocolSupportEnumeration' => 'urn:oasis:names:tc:SAML:2.0:protocol',
            'md:Extensions' => [
                'init:RequestInitiator' => [
                    '@xmlns:init' => 'urn:oasis:names:tc:SAML:profiles:SSO:request-init',
                    '@Binding' => 'urn:oasis:names:tc:SAML:profiles:SSO:request-init',
                    '@Location' => str_replace('//saml', '/saml', $this->parameterBag->get('app_url') . '/saml/login'),
                ],
            ],
        ];
    }

    public function getEncryptionMethod(): array
    {
        return [
            [
                '@Algorithm' => 'http://www.w3.org/2009/xmlenc11#aes128-gcm',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2009/xmlenc11#aes192-gcm',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmlenc#aes192-cbc',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
            ],
            [
                '@Algorithm' => 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
            ],
        ];
    }
    public function getKeyDescriptor(): array
    {
        return [
            '@use' => 'signing',
            'ds:KeyInfo' => [
                '@xmlns:ds' => 'http://www.w3.org/2000/09/xmldsig#',
                'ds:KeyName',
                'ds:X509Data' => [
                    'ds:X509Certificate' => str_replace("-----BEGIN CERTIFICATE-----\n", '', str_replace("\n-----END CERTIFICATE-----", '', $this->parameterBag->get('app_x509_cert'))),
                ],
            ],
            'md:EncryptionMethod' => $this->getEncryptionMethod(),
        ];
    }

    public function getArtifactResolutionService(): array
    {
        return [
            '@Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
            '@Location' => $this->parameterBag->get('app_url') . 'saml/Artifact/SOAP',
            '@index' => '0',
        ];
    }

    public function getSingleLogoutService(): array
    {
        return [
            [
                '@Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP',
                '@Location' => $this->parameterBag->get('app_url') . 'saml/SLO/SOAP',
            ],
            [
                '@Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                '@Location' => $this->parameterBag->get('app_url') . 'saml/SLO/Redirect',
            ],
            [
                '@Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                '@Location' => $this->parameterBag->get('app_url') . 'saml/SLO/POST',
            ],
            [
                '@Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact',
                '@Location' => $this->parameterBag->get('app_url') . 'saml/SLO/Artifact',
            ],
        ];
    }

    public function getAssertionConsumerService(): array
    {
        return [
            [
                '@Binding'  => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                '@Location' => $this->parameterBag->get('app_url').'saml/SAML2/POST',
                '@index'    => '0',
            ],
            [
                '@Binding'  => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign',
                '@Location' => $this->parameterBag->get('app_url').'saml/SAML2/POST-SimpleSign',
                '@index'    => '1',
            ],
            [
                '@Binding'  => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact',
                '@Location' => $this->parameterBag->get('app_url').'saml/SAML2/Artifact',
                '@index'    => '2',
            ],
        ];
    }

    public function getMetaData(): array
    {
        return [
            '@xmlns:md'     => 'urn:oasis:names:tc:SAML:2.0:metadata',
            '@ID'           => '_09cbf496-24af-4cdc-91c3-b28bbda9f79f',
            '@entityID'     => $this->parameterBag->get('app_url').'saml',
            'md:Extensions' => $this->getExtensions(),
            'md:SPSSODescriptor' => $this->getSPSSODescriptor(),
            'md:KeyDescriptor' => $this->getKeyDescriptor(),
            'md:ArtifactResolutionService' => $this->getArtifactResolutionService(),
            'md:SingleLogoutService' => $this->getSingleLogoutService(),
            'md:AssertionConsumerService' => $this->getAssertionConsumerService(),
        ];
    }
}