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
class StageFileProxy extends Audit {

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

    $module_to_check = $sandbox->getParameter('module_to_check');

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

    if(!$lagoon_env_type) {
      $msg = 'Cannot determinate the environment (production or not).' . PHP_EOL;
      $sandbox->setParameter('warning_message', $msg);
      return Audit::WARNING;
    }

    $info = $sandbox->drush(['format' => 'json'])->pmList();

    if (!isset($info[$module_to_check])) {
      $msg = "Module {$module_to_check} has not been found on this server." . PHP_EOL;
      $sandbox->setParameter('warning_message', $msg);
      return Audit::WARNING;
    }

   $module_status = strtolower($info[$module_to_check]['status']);

    if( $module_status === 'enabled' && $lagoon_env_type === 'production') {
      $msg = "Module {$module_to_check} is enabled on this production environment." . PHP_EOL;
      $msg .= 'You should disable it.' . PHP_EOL;
      $sandbox->setParameter('status', $msg);
      return Audit::FAILURE;
    }

    if( $module_status !== 'enabled' && $lagoon_env_type !== 'production') {
      $msg = "Module {$module_to_check} is NOT enabled on this development environment." . PHP_EOL;
      $msg .= 'You should enable it.' . PHP_EOL;
      $sandbox->setParameter('status', $msg);
      return Audit::FAILURE;
    }

    $sandbox->setParameter('status', "Module {$module_to_check} is {$module_status} on this {$lagoon_env_type} environment.");
    return Audit::SUCCESS;
  }

} //end class