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

namespace Unit4;

class HttpRequest
{
    /**
     * Holds our base path. In most cases this is just /, but it can be /api for example
     * @var type 
     */
    protected $base_path = "/";

    /**
     * Base URL without leading /
     * @var string
     */
    protected $base_url = "";

    /**
     * HTTP request status
     * @var type
     */
    protected $http_status = null;

    /**
     * HTTP status code
     * @var type
     */
    protected $http_status_code = null;

    /**
     * Request response headers AS array
     * @var type
     */
    protected $response_headers = null;

    /**
     * The request return data
     * @var type
     */
    protected $response_data = null;

    /**
     * Construct new HttpRequest
     * @param string $base_path Base path like, / or /api
     * @param string $base_url Base url like http://api.website.com without leading /
     */
    public function __construct($base_path = "/", $base_url = "") {            
        $this->base_path = $base_path;
        $this->base_url = $base_url;
    }

    /**
     * Set Base URL
     * @param type $url
     */
    public function setBaseURL($url = ""){
        $this->base_url = $url;
        return $this;
    }

    /**
     * HTTP POST request
     * @param type $path
     * @param type $headers
     * @param type $parameters
     */
    public function Post($path = "", $headers = array(), $parameters = array()){
        //Sen the request and return response
        return $this->http_request(
            "POST", 
            $this->base_url.$this->base_path.$path, 
            $headers,
            $parameters
        );
    }

    /**
     * HTTP GET request
     * @param type $path
     * @param type $headers
     * @param type $parameters
     */
    public function Get($path = "", $headers = array(), $parameters = array()){
        //Sen the request and return response
        return $this->http_request(
            "GET", 
            $this->base_url.$this->base_path.$path, 
            $headers,
            $parameters
        );
    }

    /**
     * Get request response headers
     * @return type
     */
    public function getHeaders(){
        return $this->response_headers;
    }

    /**
     * Get request response data
     * @return type
     */
    public function getData(){
        return $this->response_data;
    }

    /**
     * Returns HTTP status
     * @return type
     */
    public function status(){
        return [$this->http_status_code, $this->http_status];
    }

    /**
     * HTTP Custom request
     * @param type $path
     * @param type $headers
     * @param type $parameters
     */
    public function Custom($method = "", $path = "", $headers = array(), $parameters = array()){
        //Sen the request and return response
        return $this->http_request(
            $method,
            $this->base_url.$this->base_path.$path,
            $headers,
            $parameters
        );
    }

    /**
    * HTTP request
    * @param type $method  GET|POST
    * @param type $headers
    * @param type $parameters
    * @return boolean
    */
   private function http_request($method = "GET", $url = "", $headers = array(), $parameters = array()){
       $opts = array(
           'http' => array(
               'method' => $method,
               'header' => '',
               'content' => '',
               'user_agent' => 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
               'timeout' => 10,
               'protocol_version' => 1.1
           ),
           'ssl' => array(
               'verify_peer' => false,
               'verify_host' => false,
               'ciphers' => 'HIGH'
           )
       );
       //Check if we have parameters to post
       if(count($parameters) > 0 && is_array($parameters)){
           $content = "";                
           foreach($parameters as $k => $v){
               $content .= "&{$k}=".$v;
           }
           //Strip first & sign
           $opts["http"]["content"] = substr($content, 1);
       }elseif($parameters){
           //Send as is
           $opts["http"]["content"] = $parameters;
       }

       //Check if we have headers to parse
       if(count($headers) > 0 && is_array($headers)){
           $content = "";                
           foreach($headers as $k => $v){
               $content .= "{$k}: {$v}\r\n";
           }
           //Strip first & sign
           $opts["http"]["header"] = trim($content);
       }
       if($opts["http"]["header"] === ""){
           unset($opts["http"]["header"]);
       } 

       //Debug
       //echo "<pre>".print_r($opts, true)."</pre>";
       //echo "\r\n".$url."\r\n<br/>";

       //Setup request
       $context = stream_context_create($opts);

       /**
        * @version 1.1 Updated method
        */
       $response = @file_get_contents($url, false, $context);

       //If we have an error or not
       if($response === FALSE){

           $error = error_get_last();
           if(preg_match("#HTTP/.* ([0-9]{3})(.+$)#is", $error["message"], $matches)){

                $this->http_status_code = (int)$matches[1];
                $this->http_status      = trim($matches[2]);
                return $this;
           }

           $this->http_status_code = 402;
           $this->response_data = "Error while requesting {$url}\r\n<br/>".print_r($error, true);
           return $this; //Request not possible
           
       }else{

           //echo "{$method} request allowed.\r\n";

            //Get and debug headers
            $req_headers = @stream_get_meta_data($response);
            //print_r($req_headers["wrapper_data"]);

            if(is_array($req_headers) && count($req_headers) > 0){
                $this->response_headers = $req_headers;
            }
            
            if(isset($req_headers["wrapper_data"])){
                //Get HTTP status
                if(preg_match("#HTTP/.* ([0-9]{3}(.+$))#is", $req_headers["wrapper_data"][0], $matches)){
                    $this->http_status_code = (int)$matches[1];
                    $this->http_status      = trim($matches[2]);
                }
                echo "<pre>".print_r($req_headers["wrapper_data"], true)."</pre>";
            }else{
                //echo "<pre>".print_r($req_headers, true)."</pre>";
            }           
            
            if(($json = @json_decode($response, true)) !== NULL){
                $this->response_data = $json;
            }else{
                $this->response_data = $response;
            }
       }

       return $this;
   }
}