<?php

require_once "autoload.php";

$sec = new theCodingCompany\Security("http://http://www.dvwa.co.uk");

$alerts = $sec->runTests()
    ->getAlerts();

echo "<pre>";
print_r($alerts);