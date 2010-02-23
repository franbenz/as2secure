<?php

/**
 * AS2Secure - PHP Lib for AS2 message encoding / decoding
 *
 * @author  Sebastien MALOT <contact@as2secure.com>
 *
 * @copyright Copyright (c) 2010, Sebastien MALOT
 *
 * Last release at : {@link http://www.as2secure.com}
 *
 * This file is part of AS2Secure Project.
 *
 * AS2Secure is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * AS2Secure is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with AS2Secure.
 *
 * @license http://www.gnu.org/licenses/lgpl-3.0.html GNU General Public License
 * @version 0.8.0
 *
 */

class AS2Header implements Countable {
    protected $headers = array();
    
    protected $_position = null;
    
    public function __construct($data = null) {
        if (is_array($data)) {
            $this->headers = $data;
        }
        elseif (is_string($data)) {
            
        }
    }
    
    public function setHeaders($headers) {
        $this->headers = $headers;
    }
    
    public function addHeader($key, $value) {
        $this->headers[$key] = $value;
    }
    
    public function removeHeader($key) {
        unset($this->headers[$key]);
    }

    public function getHeaders() {
        return $this->headers;
    }
    
    public function getHeader($token) {
        $token = strtolower($token);
        $tmp = array_change_key_case($this->headers);
        if (isset($tmp[$token])) return $tmp[$token];
        return false;
    }
    
    public function count() {
        return count($this->headers);
    }
    
    public function exists($key) {
        $tmp = array_change_key_case($this->headers);
        return array_key_exists(strtolower($key), $tmp);
    }
    
    public function __toString() {
        $ret = '';
        
        foreach($this->headers as $key => $value) {
            $ret .= $key . ': ' . $value . "\n";
        }
        
        return rtrim($ret);
    }
    
    public static function parseText($text) {
        $headers = array();
        if (strpos($text, "\n\n") !== false) $text = substr($text, 0, strpos($text, "\n\n"));

        $matches = array();
        preg_match_all('/(.*?):\s*(.*?\n(\s.*?\n)*)/', $text, $matches);
        if ($matches) {
            foreach($matches[2] as &$value) $value = str_replace(array("\r", "\n"), ' ', $value);
            unset($value);
            $headers = array_combine($matches[1], $matches[2]);
        }
        
        return new self($headers);
    }
    
    public static function parseHttpRequest() {
        /**
         * Fix to get request headers from Apache even on PHP running as a CGI
         *
         */
        if( !function_exists('apache_request_headers') ) {
            $headers = array();
    
            foreach($_SERVER as $key => $value){
                if (strpos('HTTP_', $key) === 0){
                    $key = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($key, 5)))));
                    $headers[$key] = $value;
                }
            }
    
            return new self($headers);
        }
        else {
            return new self(apache_request_headers());
        }
    }
}
