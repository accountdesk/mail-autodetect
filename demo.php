<?php

require_once __DIR__ . '/vendor/autoload.php';

use MailAutodetect\AutoDetector;

$a = new AutoDetector();

// Test autoDetect
print_r($a->autoDetect("outlook.com"));
print_r($a->autoDetect("gmx.de"));
print_r($a->autoDetect("stud.uni-goettingen.de"));
print_r($a->autoDetect("accountone.de"));
print_r($a->autoDetect("skrueger.dev"));
print_r($a->autoDetect("kruegersabine.de"));
