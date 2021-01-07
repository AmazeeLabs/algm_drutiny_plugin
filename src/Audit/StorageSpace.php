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
 *  name = "threshold_percent",
 *  type = "integer",
 *  description = "Storage space threshold to notify if disk space is under",
 * )
 */
class StorageSpace extends Audit {
  const MAX_STRING_LENGTH = 60;

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

    $threshold = (int) $sandbox->getParameter('threshold_percent');
    $status = $sandbox->drush(['format' => 'json'])->status();

    if ($status === null) {
      return AUDIT::ERROR;
    }

    try {
      $output = $sandbox->exec("df -H");
    }
    catch (Exception $e) {
      return Audit::ERROR;
    }

    $disk = array_map(function($line) {
      $elements = preg_split('/\s+/', $line);
      return([
        'filesystem' => isset($elements[0]) ? $elements[0] : '',
        'size' => isset($elements[1]) ? $elements[1] : '',
        'used' => isset($elements[2]) ? $elements[2] : '',
        'available' => isset($elements[3]) ? $elements[3] : '',
        'use%' => isset($elements[4]) ? $elements[4] : '',
        'mounted' => isset($elements[5]) ? $elements[5] : '',
      ]);
    }, explode("\n",$output));

    array_shift($disk);
    $storage_warnings = [];
    foreach ($disk as $item) {
      if (!empty($item['use%'])) {
        $use = (int) str_replace('%', '', $item['use%']);
        if ((100-$use) <= $threshold) {
          $free_space = 100 - (int) str_replace('%', '', $item['use%']) . '%';
          $storage_warnings[] = "⚠️\t" .$item['filesystem'] . ' free space: ' . $free_space;
        }
      } //end if
    } //end for

    if (count($storage_warnings)) {
      $msg = "The following filesystems are below or equal to the threshold ({$threshold}%)." . PHP_EOL;
      foreach ($storage_warnings as $item) {
        $msg .= $item . PHP_EOL;
      }
      $sandbox->setParameter('warning_message', $msg);
      return Audit::FAIL;
    }

    $sandbox->setParameter('status', "All filesystems have free space above threshold ({$threshold}%).");
    return Audit::SUCCESS;
  }
}
