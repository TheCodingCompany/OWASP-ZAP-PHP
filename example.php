<?php

require_once "autoload.php";

$sec = new theCodingCompany\Security("https://www.dvwa.co.uk");

$credentials = [
    "login"         => "admin",
    "wachtwoord"    => "admin123"
];
$alerts = $sec->setFormAuthentication($credentials, "https://www.dvwa.co.uk")
            ->runTests()
            ->getAlerts();

print_r($alerts);