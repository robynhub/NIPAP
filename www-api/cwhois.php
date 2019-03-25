<?php

/* 
 * Whois di una classe su NIPAP
 * Output in formato console
 */

include 'lib/api.php';
include 'config.php';


$query = $_GET['query'];
$result = smartquery($query);
$result = array_reverse($result);
$output = "";



foreach ($result as $id => $prefix) {
    foreach ($whois_cols as $col ) {
        $output .= strtoupper($col) . ":";
        $len = strlen($col);

        //identation fix        
        for ($i = 0 ;  $i < $n_tabs-floor($len/8) ; $i++)
            $output .= "\t";

        switch ($col) {
        case 'added':
        case 'last_modified':
            // modifico la visualizzazione delle date
            $output .= sanitize_date($result[$id][$col]);
            break;
        case 'type':
            // Inserisco la maiuscola
            $output .= ucwords($result[$id][$col]);
            break;
        case 'prefix':
            $output .= cidr_to_range($result[$id][$col]);
            break;
        case 'tags':
        case 'inherited_tags':
            $output .= sanitize_tags($result[$id][$col]);
            break;
        case 'vrf_rt':
            if ($result[$id][$col] == "")
                $output .= "none";
            else
                $output .= $result[$id][$col];
            break;
        default:
            $output .= $result[$id][$col];
        
        }
        $output .= "\n";
    }
    $output .= "\n";
}
header('Content-Type: text/plain');
header('Content-Length: ' . strlen($output));
header('Connection: close');
// raw data
if ($debug) echo  var_export($result , true) . "\n\n";
echo $output;

?>