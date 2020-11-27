<?php

namespace Drutiny\algm\Audit;

use Drutiny\Audit;
use Drutiny\Profile\ProfileSource;
use Drutiny\Sandbox\Sandbox;
use Drutiny\AuditResponse\AuditResponse;
use Drutiny\Annotation\Param;
use Drutiny\Annotation\Token;
use Drutiny\algm\Utils\MarkdownTableGenerator;
use Drutiny\Report\Format;

/**
 * Scan files in a directory for matching regex.
 * @Param(
 *  name = "directory",
 *  description = "Absolute filepath to directory to scan",
 *  type = "string",
 *  default = "%root"
 * )
 * @Param(
 *  name = "exclude",
 *  description = "Absolute filepaths to directories omit from scanning",
 *  type = "array",
 *  default = {}
 * )
 * @Param(
 *  name = "filetypes",
 *  description = "file extensions to include in the scan",
 *  type = "array",
 *  default = {}
 * )
 * @Token(
 *   name = "results",
 *   description = "An array of results matching the scan criteria. Each match is an assoc array with the following keys: filepath, line, code, basename.",
 *   type = "array",
 *   default = {}
 * )
 */
class DoubleFileExtension extends Audit {

  public function audit(Sandbox $sandbox) {
    $directory = $sandbox->getParameter('directory', '%root');
    $stat = $sandbox->drush(['format' => 'json'])->status();

    $directory =  strtr($directory, $stat['%paths']);

    $command = ['find', $directory];

    foreach ($sandbox->getParameter('exclude', []) as $filepath) {
        $filepath = strtr($filepath, $stat['%paths']);
        $command[] = "-path '$filepath'";
      }

    $command[] = "-prune -type f -o -regextype egrep -regex";

    $types = $sandbox->getParameter('filetypes', []);

    if (!empty($types)) {
      $conditions = [];
      foreach ($types as $type) {
        $conditions[] = $type;
      }
      $command[] = '".*\.(' . implode('|', $conditions) . ')\.[^\.]+$" -printf "%p %TY-%Tm-%Td\n"';
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
      list($filepath, $date) = explode(' ', $line);
      return [
        'file' => $filepath,
        'date' => $date,
        'basename' => basename($filepath),
        'display' => $filepath . ' ' . $date
      ];
    }, $matches);

    $matches = array_filter($matches, function($line) {
      return !strpos($line['basename'], 'js.gz') !== false;
    });

    $results = [
      'found' => count($matches),
      'findings' => $matches,
      'filepaths' => array_values(array_unique(array_map(function ($match) use ($stat) {
        return str_replace($stat['%paths']['%root'], '', $match['file']);
      }, $matches)))
    ];

    //TODO: Add a conditional check for Markdown format
    $columns = ['Basename', 'Date', 'Filename'];
    $rows = [];
    foreach ($results['findings'] as $key => $file) {
        $rows[] = [$file['basename'], $file["date"], $file["file"]];
    }

    $md_table = new MarkdownTableGenerator($columns, $rows);
    $results['findings'] = ['markdown_display' => $md_table->render()];

    $sandbox->setParameter('results', $results);

    if (empty($matches)) {
        Audit::SUCCESS;
    }
    return Audit::FAIL;
  }

}