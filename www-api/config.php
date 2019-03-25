<?php

// debug
$debug = false;

// impostazioni connessione
$conn = 'http://guest:guest@127.0.0.1:1337/XMLRPC';
$auth = array('authoritative_source' => 'nipap');


///////////////////////////
////////// WHOIS //////////
///////////////////////////

$max_records = 200;

//formato data (uso standard whois)
$date_format = 'Y-m-d\TH:i:s\Z';

//numero di tab per la visualizzazione in console
$n_tabs = 3;

// colonne in ordine da includere nelle smartquery
$whois_cols = array(
	'prefix',
	'description',
	'type',
	'added',
	'tags',
	'inherited_tags',
	'last_modified',
	'vrf_name',
	'vrf_rt',
	'id'
	);

?>