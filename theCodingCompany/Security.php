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
     * Found security issues
     * @var array
     */
    protected $alerts = [];

    /**
     * Construct new Securit Scanner
     * @param type $url
     */
    public function __construct($url = "/")
    {
        $this->target = $url;
        $this->http = new HttpRequest("/", self::API_URL);
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
     * Main method to call for automated security testing
     */
    public function runTests()
    {
        echo "Using version: " . $this->version() . "\r\n";

        if($this->startSpider()){ //If spider finished
            
            if($this->startScan()){ //Start security scan, if finished grab results

                $this->getScanResults();
            }
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
        $parameters = [
            "zapapiformat"  => "JSON",
            "apikey"        => self::API_KEY,
            "url"           => $this->target,
        ];

        $r = $this->http->Post("JSON/ascan/action/scan/", [], $parameters);
        $response = $r->getData();
        if(isset($response["scan"]) && $response["scan"] >= 0){
            $this->scan_id = (int)$response["scan"];

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
        $parameters = [
            "apikey"        => self::API_KEY,
            "zapapiformat"  => "JSON",
            "url"           => $this->target
        ];

        $r = $this->http->Post("JSON/spider/action/scan/", [], $parameters);
        $response = $r->getData();
        if(isset($response["scan"]) && $response["scan"] >= 0){
            $this->spider_scan_id = (int)$response["scan"];

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