<?php


namespace Conduction\SamlBundle\Controller;

use Conduction\SamlBundle\Service\SamlService;
use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Error;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Serializer\Encoder\XmlEncoder;

/**
 * Class SamlController.
 */
class SamlController extends AbstractController
{
    private Auth $samlAuth;
    private XmlEncoder $xmlEncoder;
    private SamlService $samlService;

    private string $enabledParameter;

    public function __construct($samlAuth, SamlService $samlService, string $enabledParameter)
    {
        $this->samlAuth = $samlAuth;
        $this->xmlEncoder = new XmlEncoder();
        $this->samlService = $samlService;
        $this->enabledParameter = $enabledParameter;
    }

    /**
     * @param Request $request
     * @throws Error
     */
    public function loginAction(Request $request)
    {
        $this->samlService->checkSamlEnabled($this->enabledParameter);
        $session = $targetPath = null;

        if ($request->hasSession()) {
            $session = $request->getSession();
            $targetPath = $session->get('_security.main.target_path');
        }
        $targetPath = $request->query->get('returnUrl') ?? $request->headers->get('referer') ?? $request->getSchemeAndHttpHost();
        $this->samlAuth->login($targetPath);
    }

    public function metadataAction(): Response
    {
        $this->samlService->checkSamlEnabled($this->enabledParameter);
        $message = $this->samlService->getMetaData($this->samlAuth->getSettings());
        $xml = $this->xmlEncoder->encode($message, 'xml', ['remove_empty_tags' => true]);

        $response = new Response($xml);

        $response->headers->set('Content-Type', 'xml');

        return $response;
    }

    public function artifactAction(Request $request)
    {
    }
}