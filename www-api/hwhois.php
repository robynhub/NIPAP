<?php

/* 
 * Whois di una classe su NIPAP
 * Output in formato html (non include tag esterni)
 */

include 'lib/api.php';
include 'config.php';


$query = $_GET['query'];
$result = smartquery($query);
$result = array_reverse($result);



foreach ($result as $id => $prefix) {
    // nuovo prefisso 
    switch ($result[$id]['type']){
    case 'assignment':
        echo "<table style='border: 1px solid #E9A002; background-color: #FFA901; background-image: -webkit-linear-gradient(top,#F0D002, #FFA901);'>\n";
        break;
    case 'reservation':
        echo "<table style='border: 1px solid #9802A4; background-color: #E802B4; background-image: -webkit-linear-gradient(top, #E802B4, #A001D9);'>\n";
        break;
    case 'host':
        echo "<table style='border: 1px solid #08A901; background-color: #02E81D; background-image: -webkit-linear-gradient(top, #02E81D, #089901);'>\n";
        break;
    default:
        echo "<table border=1>\n";
    }
    
    
    foreach ($whois_cols as $col ) {
        echo "<tr>\n";
        echo "<td>\n";
        echo strtoupper($col) . "</td>\n<td>\n";
       
        switch ($col) {
        case 'added':
        case 'last_modified':
            // modifico la visualizzazione delle date
            echo sanitize_date($result[$id][$col]);
            break;
        case 'type':
            // Inserisco la maiuscola
            echo ucwords($result[$id][$col]);
            break;
        case 'prefix':
            echo cidr_to_range($result[$id][$col]);
            break;
        case 'tags':
        case 'inherited_tags':
            echo sanitize_tags($result[$id][$col]);
            break;
        case 'vrf_rt':
            if ($result[$id][$col] == "")
               echo "none";
            else 
                echo $result[$id][$col];
            break;
        default:
            echo $result[$id][$col];
        
        }
        echo "</td></tr>";
    }
    echo "</table><br>";
}
// raw data
if ($debug) echo  var_export($result , true) . "\n\n";


?>