<?php

require_once __DIR__ . '/src/AutoDetector.php';

use MailAutodetect\AutoDetector;

$a = new AutoDetector();

// Test autoDetect
$url = "outlook.com";
$start = microtime(true);
print_r($a->autoDetect($url));
echo "$url:" . (microtime(true) - $start) . " \n";
$url = "gmx.de";
$start = microtime(true);
print_r($a->autoDetect($url));
echo "$url:" . (microtime(true) - $start) . " \n";
$url = "stud.uni-goettingen.de";
$start = microtime(true);
print_r($a->autoDetect($url));
echo "$url:" . (microtime(true) - $start) . " \n";
$url = "accountone.de";
$start = microtime(true);
print_r($a->autoDetect($url));
echo "$url:" . (microtime(true) - $start) . " \n";
$url = "skrueger.dev";
$start = microtime(true);
print_r($a->autoDetect($url));
echo "$url:" . (microtime(true) - $start) . " \n";
$url = "kruegersabine.de";
$start = microtime(true);
print_r($a->autoDetect($url));
echo "$url:" . (microtime(true) - $start) . " \n";
