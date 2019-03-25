<?php

/* 
 * Libreria per funzioni di accesso a NIPAP
 */
 
 
/* 
* Query Prefix
*/
function smartquery($message) {
 include 'config.php';
 require_once 'XML/RPC2/Client.php';
 $client = XML_RPC2_Client::create($conn);
 $result = '';
try {
	$result = $client->smart_search_prefix(array(
		 	'auth' => $auth,
		 	'query_string' => $message,
		 	'search_options' => array(
		 		'include_all_parents' => False,
		 		'max_result' => $max_records
		 		)
		 	)
	);
} catch (XML_RPC2_FaultException $e) {
	// The XMLRPC server returns a XMLRPC error
	$result = 'Exception #' . $e->getFaultString();
	return $result;
} catch (Exception $e) {  
	// Other errors (HTTP or networking problems...)
	$result = 'Exception : ' . $e->getMessage();
	return $result;
}
if ($debug) echo '<pre>' . var_export($result , true) . '</pre><ll>';
return $result['result'];
}

/* 
* Query VRF
*/
function smart_search_vrf($message) {
 include 'config.php';
 require_once 'XML/RPC2/Client.php';
 $client = XML_RPC2_Client::create($conn);
 $result = '';
try {
 	$result = $client->smart_search_vrf(array(
 		 	'auth' => $auth,
 		 	'query_string' => $message,
 		 	'search_options' => array(
 		 		'include_all_parents' => False,
 		 		'max_result' => $max_records
 		 		)
 		 	)
 	);
} catch (XML_RPC2_FaultException $e) {
 	// The XMLRPC server returns a XMLRPC error
 	$result = 'Exception #' . $e->getFaultString();
 	return $result;
} catch (Exception $e) {  
 	// Other errors (HTTP or networking problems...)
 	$result = 'Exception : ' . $e->getMessage();
 	return $result;
}

//if ($debug) echo '<pre>' . var_export($result , true) . '</pre><ll>';
return $result['result'];
}

function sanitize_date($date) {
	include 'config.php';
	return date( $date_format,$date->timestamp);
}

function sanitize_tags($tags) {
	include 'config.php';
	if (sizeof($tags) == 0)
		return 'none';
	
	$ret = $tags[0];
	
	for ($i = 1 ;$i < sizeof($tags) ; $i++)
		$ret .= " " . $tags[$i];
	
	return $ret;
}




function cidr_to_range($prefix) {
	require_once 'lib/ip-lib/ip-lib.php';
	if (preg_match('/:/', $prefix))
		return $prefix;
	
	$range = \IPLib\Factory::rangeFromString($prefix);
	return (string)$range->getStartAddress() . " - " . (string)$range->getEndAddress();
	
}
 
?>