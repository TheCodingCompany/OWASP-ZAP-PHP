#Download and install WASP ZAP 2.7

https://github.com/zaproxy/zaproxy/wiki/Downloads

#Howto

Set API_KEY in Security.php. You find this key in OWASP ZAP

```
$sec = new theCodingCompany\Security("http://http://www.dvwa.co.uk");
$alerts = $sec->runTests()
            ->getAlerts();

print_r($alerts);  //Array with "Hight", "Low" etc vulnerabilities
```

## Check Example.php