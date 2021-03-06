<?php

namespace Drutiny\algm\Audit;

use Drutiny\Annotation\Token;
use Drutiny\Audit;
use Drutiny\Sandbox\Sandbox;

/**
 * Simple Drush Status test
 *
 * @Token(
 *  name = "status",
 *  type = "string",
 *  description = "Results from Drush status"
 * )
 */
class DrushStatus extends Audit {

  /**
   * @inheritdoc
   */
  public function audit(Sandbox $sandbox) {
    $status = $sandbox->drush()->status();

    if ($status === null) {
      // If null, then status can't be found.
      return AUDIT::ERROR;
    }

    $sandbox->setParameter('status', $status);

    return Audit::SUCCESS;
  }
}
