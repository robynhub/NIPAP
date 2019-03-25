<?php

/* 
 * Whois di una classe su NIPAP
 * Output in formato jSON
 */

include 'lib/api.php';
include 'config.php';

$query = $_GET['query'];
$result = smartquery($query);
$ret = array();
    
foreach ($result as $id => $prefix) {
    foreach ($whois_cols as $col ) {
        switch ($col) {
            case 'added':
            case 'last_modified':
                // modifico la visualizzazione delle date
                $ret[$id][$col] = sanitize_date($result[$id][$col]);
                break;   
            case 'prefix':
                $ret[$id][$col] = $result[$id][$col];
                $ret[$id]['range'] = cidr_to_range($result[$id][$col]);
                break;
            case 'tags':
            case 'inherited_tags':
                $ret[$id][$col] = sanitize_tags($result[$id][$col]);
                break;
            default:
                $ret[$id][$col] = $result[$id][$col];  
        }
    }
}
$ret = array_reverse($ret);

if ($debug) echo '<pre>' . var_export($ret , true) . '</pre><ll>';

echo json_encode($ret , 1);



?>