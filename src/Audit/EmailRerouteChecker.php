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

    // Not in actual use for now
    $module_to_check = $sandbox->getParameter('module_to_check');

    $status_output = '';
    $status = $sandbox->drush(['format' => 'json'])->status();
    if (!$status) {
      return Audit::ERROR;
    }

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
    // print $lagoon_env_type . PHP_EOL;
    if(!$lagoon_env_type) {
      $msg = 'Cannot determinate the environment.' . PHP_EOL;
      $sandbox->setParameter('warning_message', $msg);
      return Audit::WARNING;
    }

    if ($lagoon_env_type === 'production') {
      $msg = 'This policy can only run in a non-production environment.' . PHP_EOL;
      $sandbox->setParameter('warning_message', $msg);
      return Audit::WARNING;
    }

   // Let's start module by module
    // because modules hav different settings
    $info = $sandbox->drush(['format' => 'json'])->pmList();

    // Reroute_email
    if (isset($info['reroute_email']) && strtolower($info['reroute_email']['status']) === 'enabled') {
      // do something
      $cmd = "drush cget reroute_email.settings --include-overridden --format=json";
      $settings = json_decode($sandbox->exec($cmd), TRUE);
      // TODO: Better logic on address condition maybe?
      if($settings['enable'] && $settings['address']) {
        $status_output = 'Reroute email is enabled.' . PHP_EOL;
        $status_output .= 'All emails are redirected to: ' . $settings['address'] . PHP_EOL;
        $sandbox->setParameter('status', trim($status_output));
        return Audit::SUCCESS;
      }
    }

    // SMTP
    if (isset($info['smtp']) && strtolower($info['smtp']['status']) === 'enabled') {
      // do something
    }

    // Swiftmailer
    // This is a quick and dirty solution
    if (isset($info['swiftmailer']) && strtolower($info['swiftmailer']['status']) === 'enabled') {
      // do something
      $cmd = "drush cget swiftmailer.transport --include-overridden --format=json";
      $settings = json_decode($sandbox->exec($cmd), TRUE);
      $smtp_host = $settings['smtp_host'];
      $search_for = 'mailhog';
      if(preg_match("/{$search_for}/i", $smtp_host)) {
        $status_output = 'SMTP host is configured to use: ' . $smtp_host . PHP_EOL;
        $sandbox->setParameter('status', trim($status_output));
        return Audit::SUCCESS;
      }
    }

    // Let's try to search in settings
    $settings_path = $status['root'] . "/sites/default";
    $cmd = 'find ' . $settings_path . ' -name "*.php" | xargs grep -i "smtp\|mail"';
    $results = $sandbox->exec($cmd);
    $files = explode(PHP_EOL, $results);
    foreach ($files as $file) {
      $search_for = 'development';
      $is_development_setting_file = preg_match("/{$search_for}/i", $file);
      $search_for = "\[\'smtp_host\'\] = \'mailhog";
      $is_using_mailhog = preg_match("/{$search_for}/i", $file);
      if ($is_development_setting_file && $is_using_mailhog) {
        $status_output = 'SMTP host is configured to use mailhog.' . PHP_EOL;
        $sandbox->setParameter('status', trim($status_output));
        return Audit::SUCCESS;
      }
    }

    // Idea: if you find instances of smtp_host in prod and dev php settings
    // then compare them
    $dev_smtp_host = '';
    $prod_smtp_host = '';
    $dev_reroute_email = '';
    foreach ($files as $file) {
      $search_for = 'development';
      $is_development_setting_file = preg_match("/{$search_for}/i", $file);
      $search_for = 'production';
      $is_production_setting_file = preg_match("/{$search_for}/i", $file);
      $search_for = "\[\'smtp_host\'\]";
      $contains_smtp_host = preg_match("/{$search_for}/i", $file);
      $search_for = "reroute_email";
      $has_reroute_in_settings = preg_match("/{$search_for}/i", $file);

      $split = "['smtp_host'] =";
      if ($is_development_setting_file && $contains_smtp_host) {
        $smtp_host = explode($split,$file);
        $dev_smtp_host = $smtp_host[1];
      }
      if ($is_production_setting_file && $contains_smtp_host) {
        $smtp_host = explode($split,$file);
        $prod_smtp_host = $smtp_host[1];
      }
      if ($is_development_setting_file && $has_reroute_in_settings) {
        $arr = explode(" = ",$file);
        $dev_reroute_email = $arr[1];
      }
    }

    $prod_smtp_host = preg_replace("/\'|\;/", "" , $prod_smtp_host);
    $dev_smtp_host = preg_replace("/\'|\;/", "" , $dev_smtp_host);
    $dev_reroute_email = preg_replace("/\'|\;/", "" , $dev_reroute_email);

    // Another case is not to have retoure_email but have something like
    // config['amag_processes.location_settings']['reroute_email_address'] = 'development+amag@amazee.com';
    // so let's try to detect something like that
    // TODO: Maybe check if lines are commented at the beginning
    // or even better get the actual config and check with site config
    if (!empty($dev_reroute_email)) {
      $status_output = "All emails are redirected to " . $dev_reroute_email . PHP_EOL;
      $sandbox->setParameter('status', trim($status_output));
      return Audit::SUCCESS;
    }

    if (!empty($prod_smtp_host)
      && !empty($dev_smtp_host)
      && $prod_smtp_host != $dev_smtp_host) {
      $status_output = "SMTP host is different on prod and dev environments." . PHP_EOL;
      $status_output .= "SMTP host in production:\t" . $prod_smtp_host . PHP_EOL;
      $status_output .= "SMTP host in environment:\t" . $dev_smtp_host . PHP_EOL;
      $status_output .= "Notice: You may want to check further these settings." . PHP_EOL;
      $sandbox->setParameter('status', trim($status_output));
      return Audit::SUCCESS;
    }

    // TODO: We definitely need more cases/scenarios to inspect
    // the above implementation is just a basic check
    // and is oriented to AmazeeIO environments
    // e.g.
    // 1. Check config folder for reroute_email records

    $status_output = 'Could not determinate the status of the SMTP host in the environment.' . PHP_EOL;
    $sandbox->setParameter('status', trim($status_output));
    return Audit::FAIL;
  }

} //end class
