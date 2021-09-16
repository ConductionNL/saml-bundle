<?php

// src/Security/TokenAuthenticator.php

/*
 * This authenticator authenticates against DigiSpoof
 *
 */

namespace Conduction\SamlBundle\Security;

use Conduction\CommonGroundBundle\Security\User\CommongroundUser;
use Conduction\CommonGroundBundle\Service\CommonGroundService;
use Doctrine\ORM\EntityManagerInterface;
use GuzzleHttp\Client;
use OneLogin\Saml2\Auth;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Symfony\Component\Serializer\Encoder\XmlEncoder;

class CommongroundSamlAdfsAuthenticator extends AbstractGuardAuthenticator
{
    private EntityManagerInterface $entityManager;
    private ParameterBagInterface $parameterBag;
    private UrlGeneratorInterface $urlGenerator;
    private Auth $samlAuth;
    private XmlEncoder $xmlEncoder;

    public function __construct(EntityManagerInterface $entityManager, ParameterBagInterface $parameterBag, UrlGeneratorInterface $urlGenerator, Auth $samlAuth)
    {
        $this->entityManager = $entityManager;
        $this->parameterBag = $parameterBag;
        $this->urlGenerator = $urlGenerator;
        $this->samlAuth = $samlAuth;
        $this->xmlEncoder = new XmlEncoder(['xml_root_node_name' => 'md:EntityDescriptor']);
    }

    /**
     * Called on every request to decide if this authenticator should be
     * used for the request. Returning false will cause this authenticator
     * to be skipped.
     */
    public function supports(Request $request)
    {
        return 'conduction_saml_artifact' === $request->attributes->get('_route')
            && $request->isMethod('POST');
    }

    /**
     * Called on every request. Return whatever credentials you want to
     * be passed to getUser() as $credentials.
     */
    public function getCredentials(Request $request)
    {
        $credentials = [
            'SAMLResponse'   => $request->request->get('SAMLResponse'),
        ];

        return $credentials;
    }

    public function samlResponseToUser(string $artifact): array
    {
        $result = base64_decode($artifact);

        $data = $this->xmlEncoder->decode($result, 'xml');
        $user = [];
        foreach($data['Assertion']['AttributeStatement']['Attribute'] as $attribute)
        {
            switch($attribute['@Name']){
                case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name':
                    $user['username'] = $attribute['AttributeValue'];
                    break;
                case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname':
                    $user['surname'] = $attribute['AttributeValue'];
                    break;
                case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname':
                    $user['givenName'] = $attribute['AttributeValue'];
                    break;
                case 'http://schemas.microsoft.com/identity/claims/displayname':
                    $user['displayName'] = $attribute['AttributeValue'];
                    break;
                case 'http://schemas.microsoft.com/identity/claims/identityprovider':
                    $user['identityProvider'] = $attribute['AttributeValue'];
                    break;
                default:
                    break;
            }
        }

        return $user;
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $user = $this->samlResponseToUser($credentials['SAMLResponse']);

        if (!isset($user['roles'])) {
            $user['roles'] = [];
        }

        if (!in_array('ROLE_USER', $user['roles'])) {
            $user['roles'][] = 'ROLE_USER';
        }

        array_push($user['roles'], 'scope.vrc.requests.read');
        array_push($user['roles'], 'scope.orc.orders.read');
        array_push($user['roles'], 'scope.cmc.messages.read');
        array_push($user['roles'], 'scope.bc.invoices.read');
        array_push($user['roles'], 'scope.arc.events.read');
        array_push($user['roles'], 'scope.irc.assents.read');

        return new CommongroundUser($user['username'], $user['identityProvider'], $user['displayName'], null, $user['roles'], $user['username'], null, 'person', false);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        return new RedirectResponse($this->urlGenerator->generate('app_default_index'));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return new RedirectResponse($this->parameterBag->get('app_url').'/saml/Login');
    }

    /**
     * Called when authentication is needed, but it's not sent.
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {

    }

    public function supportsRememberMe()
    {
        return true;
    }

    protected function getLoginUrl()
    {
        if ($this->parameterBag->get('app_subpath') && $this->parameterBag->get('app_subpath') != 'false') {
            return '/'.$this->parameterBag->get('app_subpath').$this->router->generate('app_user_digispoof', [], UrlGeneratorInterface::RELATIVE_PATH);
        } else {
            return $this->router->generate('app_user_digispoof', [], UrlGeneratorInterface::RELATIVE_PATH);
        }
    }
}
