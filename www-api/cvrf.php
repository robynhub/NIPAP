<?php

/* 
 * Whois di una classe su NIPAP
 * Output in formato console
 */

include 'lib/api.php';
include 'config.php';


// Stringa query
$query = $_GET['query'];
if (is_null($query))
    $query = "15605";
     

$result = smart_search_vrf($query);
//if ($debug) echo '<pre>' . var_export($result , true) . '</pre><ll>';
//$result = array_reverse($result);
$output = "";



foreach ($result as $id => $vrf) {
    if ($vrf['rt'] == "")
        continue;
    $vrf_num = explode(':',$vrf['rt']);
    $ASN = $vrf_num[0];
    $vrf_num = $vrf_num[1];
    $output .= "ip vrf $vrf_num\n";
    $output .= "  description " . $vrf['description'] . "\n";
    $output .= "  rd " . $vrf['rt'] . "\n";
    $output .= "  route-target export " . $vrf['rt'] . "\n";
    $output .= "  route-target import " . $vrf['rt'] . "\n";  

    if (is_array($vrf['tags']) && in_array("AUTO-BGP", $vrf['tags'])){
       //$output .=  "\n";
       $output .=  "router bgp " . $ASN . "\n";
       $output .=  "  address-family ipv4 vrf " . $vrf_num . "\n";
       $output .=  "  redistribute static\n";
       $output .=  "  redistribute connected\n";
       $output .=  "end\n";
    }
    $output .=  "\n";
}
header('Content-Type: text/plain');
header('Content-Length: ' . strlen($output));
header('Connection: close');
// raw data
if ($debug) echo  var_export($result , true) . "\n\n";
echo $output;

?>