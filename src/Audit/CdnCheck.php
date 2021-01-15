<?php

namespace Drutiny\algm\Audit;

use Drutiny\algm\Utils\Common;
use Drutiny\Annotation\Param;
use Drutiny\Audit;
use Drutiny\Sandbox\Sandbox;
use Drutiny\Annotation\Token;
use IPLib\Factory;


/**
 * Simple Drush Status test
 *
 * @Param(
 *  name = "cdn",
 *  description = "Set which CDN we are checking for.",
 *  type = "string"
 * )
 * @Token(
 *  name = "status",
 *  type = "string",
 *  description = "Results from Drush status"
 * )
 */
class CdnCheck extends Audit {

  /**
   * Returns a list of ip address for CDNs
   *
   * @return \string[][]
   */
  private function cdnIpAddresses() {
    $cdns = [
      // you get a list of fastly IPs from here
      // I have hardcoded them encase the sever we use cannot ping out.
      // https://api.fastly.com/public-ip-list
      "fastly" => [
        "23.235.32.0/20",
        "43.249.72.0/22",
        "103.244.50.0/24",
        "103.245.222.0/23",
        "103.245.224.0/24",
        "104.156.80.0/20",
        "146.75.0.0/16",
        "151.101.0.0/16",
        "157.52.64.0/18",
        "167.82.0.0/17",
        "167.82.128.0/20",
        "167.82.160.0/20",
        "167.82.224.0/20",
        "172.111.64.0/18",
        "185.31.16.0/22",
        "199.27.72.0/21",
        "199.232.0.0/16",
        "2a04:4e40::/32",
        "2a04:4e42::/32",
      ],
    ];
    return $cdns;
  }

  /**
   * Extract the host from a url.
   *
   * @param $url
   *
   * @return mixed
   */
  private function getHost($url){
    $parse = parse_url($url);
    return $parse['host'];
  }


  /**
   * @inheritdoc
   */
  public function audit(Sandbox $sandbox) {
    $cdn = $sandbox->getParameter('cdn');

    $command = "printenv";
    $output = $sandbox->exec($command);
    $env = Common::envStringToAssociativeArray($output);

    if (!$env) {
      throw new \Exception("Could not fetch environment variables.");
      return Audit::ERROR;
    }

    $url = $env['LAGOON_ROUTE'];
    if (!$url) {
      throw new \Exception("The route could not be found.");
      return Audit::ERROR;
    }

    $host = $this->getHost($url);
    $hostIp = gethostbyname($host);
    $cdnIpAddresses = $this->cdnIpAddresses();
    if ($selectedCdn = $cdnIpAddresses[$cdn]) {
      foreach ($selectedCdn as $ip) {
        $range = Factory::rangeFromString($ip);
        $address = Factory::addressFromString($hostIp);
        if ($range->contains($address)) {
          $msg = sprintf('The domain %s (%s) has been found in the ip range of %s which matches the %s CDN', $url, $hostIp, $ip, ucfirst($cdn));
          $sandbox->setParameter('status', $msg);
          return Audit::PASS;
        }
      }
    }
    else {
      throw new \Exception(sprintf("Could not find any ip addresses matching the CDN named %s", $cdn));
      return Audit::ERROR;
    }

    $msg = sprintf('The domain %s (%s) has not been found using the %s CDN ', $url, $hostIp, ucfirst($cdn));
    $sandbox->setParameter('status', $msg);
    return Audit::FAILURE;
  }

}
