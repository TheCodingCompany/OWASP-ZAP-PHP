<?php
/**
 * Intellectual Property of Svensk Coding Company AB - Sweden All rights reserved.
 * 
 * @copyright (c) 2016, Svensk Coding Company AB
 * @author V.A. (Victor) Angelier <victor@thecodingcompany.se>
 * @version 1.0
 * @license http://www.apache.org/licenses/GPL-compatibility.html GPL
 * 
 */
namespace theCodingCompany;

class Security
{
    /**
     * OWASP ZAP API key
     */
    const API_KEY = "";

    /**
     * URL to OWASP Zap API
     */
    const API_URL = "http://localhost:8080";

    /**
     * Session management for HTTP form authentication
     */
    const SESSION_FORM_AUTH = "httpAuthSessionManagement";

    /**
     * The FQDN to scan
     * @var string 
     */
    protected $target = "";

    /**
     * HTTP Request
     * @var object
     */
    protected $http = null;

    /**
     * The API response data object
     * @var object | array
     */
    protected $response_data = null;

    /**
     * HTTP Urls found by the spider
     * @var array
     */
    protected $knowledge_base = [];

    /**
     * The scan ID of our spider scan
     * @var int
     */
    protected $spider_scan_id = -1;

    /**
     * Active security scan id
     * @var int
     */
    protected $scan_id = -1;

    /**
     * ContextID
     * @var int
     */
    protected $context_id = 2;

    /**
     * Found security issues
     * @var array
     */
    protected $alerts = [];

    /**
     * The ID of the API user for use with Form Authentication
     * @var int
     */
    protected $api_user_id = -1;

    /**
     * Construct new Securit Scanner
     * @param type $url
     */
    public function __construct($url = "/")
    {
        $this->target = $url;
        $this->http = new HttpRequest("/", self::API_URL);

        //Always create a context
        if(($this->context_id = $this->createContext()) === false){
            echo "Failed to create Context.\r\n";
            exit(0);
        }else{
            echo "Context set or created.\r\n";
        }
    }

    /**
     * Get the found vunlerabilities
     * @return type
     */
    public function getAlerts()
    {
        return $this->alerts;
    }

    /**
     * Enable our API user
     * @return boolean
     */
    private function enableUser()
    {
        $r = $this->http->Get("JSON/users/action/setUserEnabled/?zapapiformat=JSON&apikey=".self::API_KEY."&formMethod=GET&contextId={$this->context_id}&userId={$this->api_user_id}&enabled=true");
        $response = $r->getData();
        if(isset($response["Result"]) && $response["Result"] === "OK"){
            return true;
        }

        return false;
    }

    /**
     * Set/add credentials to our user
     * @param string $username
     * @param string $password
     * @return boolean
     */
    private function setCredentials($username, $password)
    {
        $parameters = [
            "zapapiformat"  => "JSON",
            "apikey"        => self::API_KEY,
            "contextId"     => $this->context_id,
            "userId"        => $this->api_user_id,
            "authCredentialsConfigParams" => urlencode("username={$username}&password={$password}")
        ];
        $r = $this->http->Post("JSON/users/action/setAuthenticationCredentials/", [], $parameters);
        list($status) = $r->status();
        if($status !== FALSE){
            if($status === 400){
                echo "Failed to set Credentials.";
                exit(0);
            }
        }
        
        $response = $r->getData();
        if(isset($response["Result"])){
            if($response["Result"] === "OK"){
                return true;
            }
        }

        return false;
    }

    /**
     * Set session management to Form Authentication
     * @return boolean
     */
    private function setSessionManagement($auth_type = self::SESSION_FORM_AUTH)
    {
        $parameters = [
            "zapapiformat"  => "JSON",
            "apikey"        => self::API_KEY,
            "contextId"     => $this->context_id,
            "methodName"    => $auth_type
        ];
        $r = $this->http->Post("JSON/sessionManagement/action/setSessionManagementMethod/", [], $parameters);
        $response = $r->getData();
        if(isset($response["Result"]) && $response["Result"] === "OK"){
            return true;
        }

        return false;
    }

    /**
     * Create a user to enable Form Authentication
     * @param string $username
     * @param string $password
     */
    private function createApiUser()
    {
        if(($id = $this->apiUserExists("ZAP-PHP-USER")) !== false){
            return (int)$id;
        }

        $parameters = [
            "zapapiformat"  => "JSON",
            "apikey"        => self::API_KEY,
            "contextId"     => $this->context_id,
            "name"          => "ZAP-PHP-USER"
        ];
        $r = $this->http->Post("JSON/users/action/newUser/", [], $parameters);
        $response = $r->getData();
        
        if(isset($response["userId"])){
            return (int)$response["userId"];
        }else{
            return false;
        }
    }

    /**
     * Check if a user already exists
     * @param string $username
     * @return boolean
     */
    private function apiUserExists($username = "")
    {
        $users = $this->getUsers();
        foreach($users as $user){
            if(isset($user["name"]) && $user["name"] === $username){
                return (int)$user["id"];
            }
        }

        return false;
    }

    /**
     * Get list of users
     * @return boolean
     */
    private function getUsers()
    {
        $r = $this->http->Get("JSON/users/view/usersList/?zapapiformat=JSON&apikey=".self::API_KEY."&formMethod=GET&contextId={$this->context_id}");
        $response = $r->getData();
        if(isset($response["usersList"])){
            return $response["usersList"];
        }

        return false;
    }


    /**
     * Handles the creation of the API user, set the credentials and Enables the user
     * @param type $username
     * @param type $password
     * @return boolean
     */
    public function handleAuthentication($username = "", $password = "")
    {
        $this->api_user_id = $this->createApiUser();
        if($this->api_user_id >= 0){
            if($this->setCredentials($username, $password) === false){
                echo "Failed to set credentials.\r\n";
                exit(0);
            }
            if($this->enableUser() === false){
                echo "Failed to enable our user\r\n";
                exit(0);
            }
        }

        return true;
    }

    /**
     * Check and get whether our Context already exists
     * @return boolean
     */
    private function contextExists()
    {
        $contexts = $this->getContexts();
        foreach($contexts as $context){
            if($context === "php-zap-api"){
                $r = $this->http->Get("JSON/context/view/context/?zapapiformat=JSON&apikey=".self::API_KEY."&formMethod=GET&contextName=php-zap-api");
                $response = $r->getData();
                if(isset($response["context"])){
                    return (int)$response["context"]["id"];
                }
            }
        }

        return false;
    }

    /**
     * Get all Contexts (list)
     * @return array
     */
    private function getContexts()
    {
        $r = $this->http->Get("JSON/context/view/contextList/?zapapiformat=JSON&apikey=".self::API_KEY."&formMethod=GET");
        $response = $r->getData();
        if(isset($response["contextList"])){
            return $response["contextList"];
        }
    }

    /**
     * Set and Enable Form Authentication
     * @param array $credentials  Key = > Value pair. Formfield name + Formfield value Ex. array("email" => "me@me.nl", "password" => "test123")
     * @param string $login_url The PATH to the login page. Ex.  /login.php /index.php
     */
    public function setFormAuthentication($credentials = [], $login_url = "")
    {
        $fields = array_keys($credentials);
        $values = array_values($credentials);
        
        $parameters = [
            "zapapiformat"              => "JSON",
            "apikey"                    => self::API_KEY,
            "contextId"                 => $this->context_id,
            "authMethodName"            => "formBasedAuthentication",
            "authMethodConfigParams"    => urlencode("loginUrl={$login_url}&loginRequestData=".urlencode("{$fields[0]}={%username%}&{$fields[1]}={%password%}"))
        ];
        $r = $this->http->Post("JSON/authentication/action/setAuthenticationMethod", [], $parameters);
        $response = $r->getData();
        if(isset($response["Result"]) && $response["Result"] === "OK"){

            if(!$this->handleAuthentication($values[0], $values[1])){
                echo "Failed to create a valid user with credentials.\r\n";
                exit(0);
            }

            echo "User created with id {$this->api_user_id} and Form Authtication enabled.\r\n";

            return $this;
        }

        return false;
    }

    /**
     * Get the ROOT url for regex
     * @return string FQDN
     */
    private function getRootUrl()
    {
        $parts = parse_url($this->target);
        return urlencode($parts["scheme"]."://".$parts["host"]);
    }

    /**
     * Include target in Context
     * @return boolean
     */
    private function includeInContext()
    {
        $parameters = [
            "zapapiformat"  => "JSON",
            "apikey"        => self::API_KEY,
            "contextName"   => "php-zap-api",
            "regex"         => ".*"
        ];
        $r = $this->http->Post("JSON/context/action/includeInContext/", [], $parameters);
        $response = $r->getData();
        if(isset($response["Result"]) && $response["Result"] === "OK"){
            return true;
        }

        return false;
    }

    /**
     * Create contextId
     * @return boolean | int
     */
    private function createContext()
    {
        if(($id = $this->contextExists()) !== false){
            return $id;
        }
        
        $r = $this->http->Get("JSON/context/action/newContext/?zapapiformat=JSON&apikey=".self::API_KEY."&formMethod=GET&contextName=php-zap-api");
        $response = $r->getData();

        if(isset($response["contextId"])){
            return (int)$response["contextId"];
        }

        return false;
    }

    /**
     * Main method to call for automated security testing
     */
    public function runTests()
    {
        echo "Using version: " . $this->version() . "\r\n";

        if($this->context_id !== -1){

            if($this->includeInContext() === false){
                echo "Not able to include {$this->getRootUrl()} into Context.\r\n";
                exit(0);
            }

            if($this->startSpider()){ //If spider finished

                if($this->startScan()){ //Start security scan, if finished grab results

                    $this->getScanResults();
                }
            }

        }else{
            echo "Error creating context. Can't continue\r\n";
            exit(0);
        }

        return $this;
    }

    /**
     * Get the security scan results
     * @return boolean
     */
    private function getScanResults()
    {
        $parameters = [
            "zapapiformat"  => "JSON",
            "apikey"        => self::API_KEY,
            "baseurl"       => $this->target,
        ];
        $r = $this->http->Post("JSON/core/view/alerts/", [], $parameters);
        $response = $r->getData();
        if(isset($response["alerts"])){
            foreach($response["alerts"] as $alert){

                if(!isset($this->alerts[$alert["risk"]])){
                    $this->alerts[$alert["risk"]] = [];
                }

                array_push($this->alerts[$alert["risk"]], [
                    "description"   => $alert["description"],
                    "risk"          => $alert["risk"],
                    "url"           => $alert["url"],
                    "alert"         => $alert["alert"],
                    "attack"        => $alert["attack"]
                ]);
            }

            return true;
        }

        return false;
    }

    /**
     * Start security scan
     * @return boolean
     */
    private function startScan()
    {
        $endpoint = "JSON/ascan/action/scan/";
        $key = "scan";

        $parameters = [
            "zapapiformat"  => "JSON",
            "apikey"        => self::API_KEY,
            "url"           => $this->target,
        ];

        if($this->api_user_id >= 0){
            $parameters["userId"]       = $this->api_user_id;
            $parameters["contextId"]    = $this->context_id;
            $endpoint = str_replace("/scan/", "/scanAsUser/", $endpoint);
            $key = "scanAsUser";
        }

        $r = $this->http->Post($endpoint, [], $parameters);
        $response = $r->getData();

        if(isset($response[$key]) && $response[$key] >= 0){
            $this->scan_id = (int)$response[$key];

            while(($progress = $this->getScanStatus()) < 100){

                //If error occured
                if($response === FALSE){ break; }

                echo "Scan progress {$progress}\r\n";
                sleep(3);
            }

            echo "Scan completed\r\n";

            return true;
        }

        return false;
    }

    /**
     * Get scan status
     * @return boolean | progress
     */
    private function getScanStatus()
    {
        $r = $this->http->Get("JSON/ascan/view/status/?zapapiformat=JSON&apikey=".self::API_KEY."&formMethod=GET&scanId={$this->scan_id}");
        $response = $r->getData();
        if(isset($response["status"])){
            return (int)$response["status"];
        }

        return false;
    }

    /**
     * Start spidering our target
     * @return boolean;
     */
    private function startSpider()
    {
        $endpoint = "JSON/spider/action/scan/";
        $key = "scan";

        $parameters = [
            "apikey"        => self::API_KEY,
            "zapapiformat"  => "JSON",
            "url"           => $this->target,
        ];

        if($this->api_user_id >= 0){
            $parameters["userId"]       = $this->api_user_id;
            $parameters["contextId"]    = $this->context_id;
            $endpoint = str_replace("scan", "scanAsUser", $endpoint);
            $key = "scanAsUser";
        }
        
        $r = $this->http->Post($endpoint, [], $parameters);
        $response = $r->getData();
        
        if(isset($response[$key]) && $response[$key] >= 0){
            $this->spider_scan_id = (int)$response[$key];

            echo "Spider created with id: {$this->spider_scan_id}\r\n";

            while(($progress = $this->getSpiderStatus()) < 100){

                //If error occured
                if($response === FALSE){ break; }

                echo "Spider progress {$progress}\r\n";
                sleep(3);
            }

            echo "Spider completed\r\n";

            return true;
        }

        return false;
    }

    /**
     * Get spider scan status
     * @return boolean | progress
     */
    private function getSpiderStatus()
    {
        $r = $this->http->Get("JSON/spider/view/status/?zapapiformat=JSON&apikey=".self::API_KEY."&formMethod=GET&scanId={$this->spider_scan_id}");
        $response = $r->getData();
        if(isset($response["status"])){
            return (int)$response["status"];
        }

        return false;
    }

    /**
     * Get the ZAP api version
     */
    private function version()
    {
        $r = $this->http->Get("JSON/core/view/version/?zapapiformat=JSON&apikey=".self::API_KEY."&formMethod=GET");

        $version = $r->getData();
        if(isset($version["version"])){
            return $version["version"];
        }
        
        return false;
    }
}