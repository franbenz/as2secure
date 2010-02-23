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

class AS2Client {
    protected $response_headers = array();
    protected $response_indice = 0;

    public function __construct()
    {
    }

    public function sendRequest($request)
    {
        if (!$request instanceof AS2Message && !$request instanceof AS2MDN) throw new AS2Exception('Unexpected format');
        
        // formatage des entetes
        $headers = $request->getHeaders();
        $tmp = array();
        foreach($headers as $key => $val){
            $tmp[] = $key.': '.$val;
        }
        $headers = $tmp;

        // initialise les variables de construction pour la recuperation des headers
        $this->response_headers = array();
        $this->response_indice  = 0;

        // envoi du fichier avec les entetes
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $request->getUrl());
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_BINARYTRANSFER, 1);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 10);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_FRESH_CONNECT, 1);
        curl_setopt($ch, CURLOPT_FORBID_REUSE, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $request->getContent());
        curl_setopt($ch, CURLOPT_USERAGENT, 'AS2Secure Php Lib');
        curl_setopt($ch, CURLOPT_HEADERFUNCTION, array($this, 'handleResponseHeader'));
        // authentication setup
        $auth = $request->getAuthentication();
        if ($auth['method'] != AS2Partner::METHOD_NONE){
            curl_setopt($ch, CURLOPT_HTTPAUTH, $auth['method']);
            curl_setopt($ch, CURLOPT_USERPWD, urlencode($auth['login']).':'.urlencode($auth['password']));
        }
        $as2_response = curl_exec($ch);
        $info         = curl_getinfo($ch);
        $error        = curl_error($ch);
        curl_close($ch);

        if ($info['http_code'] != 200)
            throw new AS2Exception('HTTP Error Code : '.$info['http_code'].'(url:'.$request->getUrl().')');
        if ($error)
            throw new AS2Exception($error);

        //$response = new AS2Request($as2_response, $this->response_headers[count($this->response_headers)-1]);
        /*var_dump($this->response_headers[count($this->response_headers)-1]);
        var_dump($as2_response);
        die();*/

        return array('request'      => $request,
                     'response'     => $as2_response,//$response,
                     'info'         => $info);
    }
    
    /**
     * Allow to retrieve HTTP headers even if there is HTTP redirections
     * 
     */
    protected function handleResponseHeader($curl, $header)
    {
        if (!trim($header) && isset($this->response_headers[$this->response_indice]) && count($this->response_headers[$this->response_indice])) $this->response_indice++;
        else {
            $pos = strpos($header, ':');
            if($pos !== false) $this->response_headers[$this->response_indice][trim(strtolower(substr($header, 0, $pos)))] = trim(substr($header, $pos+1));
        }
        return strlen($header);
    }
}
