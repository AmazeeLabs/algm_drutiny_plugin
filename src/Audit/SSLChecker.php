<?php

namespace Drutiny\algm\Audit;

use Drutiny\algm\Utils\Common;
use Drutiny\Audit;
use Drutiny\Sandbox\Sandbox;
use Drutiny\Annotation\Token;
use Drutiny\Annotation\Param;
use Spatie\SslCertificate\SslCertificate;


/**
 * SSL checker. Checks if the certificate for the given
 * domain is valid. Returns a warning when the certificate
 * is close to expire.
 *
 * @Param(
 *  name = "warning_days",
 *  description = "Display a warning if days to expire is bellow that",
 *  type = "integer"
 * )
 * @Token(
 *  name = "status",
 *  type = "string",
 *  description = "TODO: add description"
 * )
 */
class SSLChecker extends Audit {

  /**
   * This will be called before audit().
   *
   * Must return TRUE to continue audit.
   */
  protected function requireContext(Sandbox $sandbox)
  {
    // TODO: Check for pre-conditions of audits in here or remove.
    // Return TRUE if pre-conditions are meet, otherwise FALSE.
    // Any protected function prefixed with "require" will be run and must return
    // TRUE for the audit method to be fired.
    return TRUE;
  }

  public function audit(Sandbox $sandbox) {
    $warning_days = $sandbox->getParameter('warning_days');

    // Execute and clean the output into usable data.
    $command = "printenv";
    $output = $sandbox->exec($command);
    $env = Common::envStringToAssociativeArray($output);

    if (!$env) {
      throw new \Exception("Could not fetch environment variables.");
      return Audit::ERROR;
    }

    $url = $env['LAGOON_ROUTE'];
    $parse = parse_url($url);
    $domain = array_key_exists('host', $parse) ? $parse['host'] : '';

    try {
      $certificate = SslCertificate::createForHostName($domain);
    }
    catch (\Exception $e) {
      throw new \Exception("Fetching certificate from domain failed: " . $e->getMessage());
      return Audit::ERROR;
    }

    $msg = [];
    $msg[] = "Certification information for domain: " . $domain . PHP_EOL;
    $msg[] = "Valid: " . ($certificate->isValid() ? 'YES' : 'NO') . PHP_EOL;
    $msg[] = "Issuer: " . $certificate->getIssuer() . PHP_EOL;
    $msg[] = "Valid from date: " . $certificate->validFromDate(). PHP_EOL;
    $msg[] = "Expiration date: " . $certificate->expirationDate(). PHP_EOL;
    $msg[] = "Lifespan in days: " . $certificate->lifespanInDays(). PHP_EOL;
    $msg[] = "Days to expire: " . $certificate->expirationDate()->diffInDays(). PHP_EOL;
    $msg[] = "Signature: " . $certificate->getSignatureAlgorithm(). PHP_EOL;
    $msg[] = "Organization: " . ($certificate->getOrganization() ?: 'N/A'). PHP_EOL;
    $msg[] = "Expired: " . ($certificate->isExpired() ? 'YES' : 'NO') . PHP_EOL;
    $msg[] = "Domains: " . (implode(', ', $certificate->getDomains())) . PHP_EOL;
    $msg[] = "Additional domains: " . (implode(', ', $certificate->getAdditionalDomains())) . PHP_EOL;

    $sandbox->setParameter('status', trim(implode($msg)));

    if ($certificate->isExpired()) {
      $msg = "Please acquire a valid SSL certificate and install it where $domain resolves";
      $sandbox->setParameter('warning_message', trim($msg));
      return Audit::FAILURE;
    }

    // Return a success with warning when certificate is about to expire
    if ($certificate->expirationDate()->diffInDays() <= (int) $warning_days) {
      $msg = 'Your certificate is about to expire in ' .$certificate->expirationDate()->diffInDays() . ' days!';
      $sandbox->setParameter('warning_message', trim($msg));
      return Audit::WARNING;
    }

    return self::SUCCESS;
  }

}
