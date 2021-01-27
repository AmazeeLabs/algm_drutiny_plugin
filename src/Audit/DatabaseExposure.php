<?php

namespace Drutiny\algm\Audit;

use Drutiny\Audit;
use Drutiny\Profile\ProfileSource;
use Drutiny\Sandbox\Sandbox;
use Drutiny\AuditResponse\AuditResponse;
use Drutiny\RemediableInterface;
use Drutiny\Annotation\Param;
use Drutiny\Annotation\Token;
use Drutiny\algm\Utils\MarkdownTableGenerator;
use Drutiny\Report\Format;

/**
 * Database exposure checks
 * @Param(
 *  name = "filetypes",
 *  description = "Database extensions to include in the check",
 *  type = "array",
 *  default = {}
 * )
 * @Param(
 *  name = "root",
 *  description = "Root directory of app",
 *  type = "string",
 *  default = "%root"
 * )
 * @Param(
 *  name = "exclude",
 *  description = "Directories to be exlcuded from the find.",
 *  type = "array",
 *  default = {}
 * )
 * @Param(
 *   name = "results",
 *   description = "An array of results matching the scan criteria. Each match is an assoc array with the following keys: filepath, line, code, basename.",
 *   type = "array",
 *   default = {}
 * )
 * @Token(
 *   name = "plural",
 *   description = "Determines if single or multi results are returned.",
 *   type = "bool",
 *   default = false
 * )
 * @Token(
 *   name = "cleaned",
 *   description = "Returns files than have been removed",
 *   type = "array",
 *   default = {}
 * )
 */
class DatabaseExposure extends Audit implements RemediableInterface {

  public function audit(Sandbox $sandbox) {
    $root = $sandbox->getParameter('root', '%root');
    $stat = $sandbox->drush(['format' => 'json'])->status();
    $root = strtr($root, $stat['%paths']);

    $command = ['find', $root];

    $filepathConditions = [];
    foreach ($sandbox->getParameter('exclude', []) as $filepath) {
      $filepath = strtr($filepath, $stat['%paths']);
      $format = "-path %s/%s";
      $filepathConditions[] = sprintf($format, $root, $filepath);
    }

    $filepathConditions = '\( ' . implode(' -o ', $filepathConditions) . ' \)';

    $command[] = sprintf("-type d %s", $filepathConditions);

    $command[] = "-prune -false -o -type f";

    $types = $sandbox->getParameter('filetypes', []);

    if (!empty($types)) {
      $conditions = [];
      foreach ($types as $type) {
        $format = '-iname \*.%s';
        $conditions[] = sprintf($format, $type);
      }

      $command[] = '\( ' . implode(' -o ', $conditions) . ' \) -readable 2> /dev/null';
    }

    $command = implode(' ', $command);
    $sandbox->logger()->info('[' . __CLASS__ . '] ' . $command);

    // Execute
    $output = $sandbox->exec($command);

    if (empty($output)) {
      return TRUE;
    }

    $matches = array_filter(explode(PHP_EOL, $output));
    $matches = array_map(function ($line) {
      return [
        'file' => $line,
        'permission' => 'readable'
      ];
    }, $matches);

    // Filters
    // $matches = array_filter($matches, function($line) {
    //     return !strpos($line['file'], '\/core\/') !== false;
    // });

    $results = [
      'found' => count($matches),
      'findings' => $matches,
      'filepaths' => array_values(array_unique(array_map(function ($match) use ($stat) {
        return str_replace($stat['%paths']['%root'], '', $match['file']);
      }, $matches)))
    ];

    //TODO: Add a conditional check for Markdown format
    $columns = ['File', 'Permission'];
    $rows = [];
    foreach ($results['findings'] as $key => $file) {
        $rows[] = [$file['file'], $file["permission"]];
    }

    $md_table = new MarkdownTableGenerator($columns, $rows);
    $results['findings'] = ['markdown_display' => $md_table->render()];

    $sandbox->setParameter('results', $results);
    $sandbox->setParameter('plural', count($results) > 1 ? 's' : '');

    if (empty($matches)) {
        Audit::SUCCESS;
    }
    return Audit::FAIL;
  }

  // This remediation step is run if the audit fails/returns false.
  public function remediate(Sandbox $sandbox) {
    $root = $sandbox->getParameter('root', '%root');
    $list = $sandbox->getParameter('results');

    $stat = $sandbox->drush(['format' => 'json'])->status();
    $root =  strtr($root, $stat['%paths']);

    $output = '';
    if (!empty($list['filepaths'])) {
      foreach ($list['filepaths'] as $file) {
          $fileToRemove = sprintf('%s%s', $root, $file);
          $output = $sandbox->exec('rm -rf ' . $fileToRemove);
      }

      $sandbox->setParameter('cleaned', $list['filepaths']);
    }

    return $this->audit($sandbox);
  }
}
