<?php

namespace Drutiny\algm\Utils;

/**
 * Generate markdown table as output from php array
 */
class Common {

  /**
   * Converts string from printenv to associative array
   *
   * @param string $input
   * @return array | null
   */
  public static function envStringToAssociativeArray($input) {
    $env = [];
    $lines = explode(PHP_EOL, $input);
    foreach ($lines as $line) {
      $split = explode("=", $line, 2);
      if ($split[0]) {
        $env[$split[0]] = $split[1];
      }
    }
    return count($env) ? $env : NULL;
  }
}