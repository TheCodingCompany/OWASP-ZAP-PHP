#Download en installeer WASP ZAP 2.7

https://github.com/zaproxy/zaproxy/wiki/Downloads

#Howto

In Security.php even API_KEY = ""; vullen. Deze vind je in OWASP ZAP.

```
$sec = new Unit4\Security("https://var.dev.verzuimsignaal2.nl/");
$alerts = $sec->runTests()
            ->getAlerts();

print_r($alerts);  //Array met "Hight", "Low" etc vulnerabilities
```
