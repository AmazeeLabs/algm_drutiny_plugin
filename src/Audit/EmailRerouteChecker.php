<?php

namespace Drutiny\algm\Audit;

use Drutiny\Audit;
use Drutiny\Sandbox\Sandbox;
use Drutiny\Annotation\Param;
use Drutiny\Annotation\Token;
use Drutiny\Target\DrushTarget;

/**
 *  Storage space notifier.
 *
 * @Token(
 *  name = "status",
 *  type = "string",
 *  description = "Status message"
 * )
 * @Token(
 *  name = "warning_message",
 *  type = "string",
 *  description = "Warning message"
 * )
 * @Param(
 *  name = "module_to_check",
 *  type = "string",
 *  description = "Module to check",
 * )
 */
class EmailRerouteChecker extends Audit {

  /**
   * Check that target is actually a DrushTarget
   *
   * @param Sandbox $sandbox
   * @return void
   */
  protected function requireDrushTarget(Sandbox $sandbox){
    return $sandbox->getTarget() instanceof DrushTarget;
  }

  /**
   * @inheritdoc
   */
  public function audit(Sandbox $sandbox) {

    // If parameter is all, then we proceed normally,
    // else we check only this one
    $module_to_check = $sandbox->getParameter('module_to_check');


    // First check that we are in a dev env
    $command = "env";
    $output = $sandbox->exec($command);

    if(!$output) {
      return Audit::ERROR;
    }

    $lines = array_filter(explode(PHP_EOL, $output));
    $lagoon_env_type ='';
    foreach ($lines as $line) {
      if(strpos($line, 'LAGOON_ENVIRONMENT_TYPE') === 0) {
        $info = explode('=',$line);
        $lagoon_env_type = $info[1];
      }
    }
    print $lagoon_env_type . PHP_EOL;
    if(!$lagoon_env_type) {
      $msg = 'Cannot determinate the environment (production or not).' . PHP_EOL;
      $sandbox->setParameter('warning_message', $msg);
      return Audit::WARNING;
    }

    if ($lagoon_env_type === 'production') {
      $msg = 'This policy can only run in a non-production environment.' . PHP_EOL;
      $sandbox->setParameter('warning_message', $msg);
      // return Audit::WARNING;
    }

    // Let's start module by module
    // because modules hav different settings
    $info = $sandbox->drush(['format' => 'json'])->pmList();

    // SMTP
    if (isset($info['smtp']) && $info['smtp']['status'] === 'enabled') {
      // do something
      print "SMTP module found" . PHP_EOL;
    }

    // Swiftmailer
    if (isset($info['swiftmailer']) && strtolower($info['swiftmailer']['status']) === 'enabled') {
      // do something
      print "SWIFTMAILER module found" . PHP_EOL;
      $cmd = "drush cget swiftmailer.transport --include-overridden --format=json";
      $settings = $sandbox->exec($cmd);
      print_r($settings);
    }

    return Audit::SUCCESS;
  }

} //end class