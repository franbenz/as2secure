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
 * @version 0.8.2
 * 
 */

class AS2MDN extends AS2Abstract {
    /**
     * Human readable message
     */
    protected $message = '';

    protected $url = '';

    /**
     * Valid tokens :
     *    
     *    action-mode                    : "manual-action" | "automatic-action"
     *    sending-mode                   : "MDN-sent-manually" | "MDN-sent-automatically"
     *    disposition-type               : "processed" | "failed"
     *    disposition-modifier           : ( "error" | "warning" ) | disposition-modifier-extension
     *    disposition-modifier-extension : (cf : AS2Exception values)
     *    encoded-message-digest         : (base64 format + digest-alg-id = "sha1" | "md5")
     *    reporting-ua                   : user-agent
     */
    protected $attributes = array('action-mode'  => self::ACTION_AUTO,
                                  'sending-mode' => self::SENDING_AUTO);

    /**
     * Refers to RFC 4130
     * http://rfclibrary.hosting.com/rfc/rfc4130/rfc4130-34.asp
     */
    const ACTION_AUTO         = 'automatic-action';
    const ACTION_MANUAL       = 'manual-action';
    
    const SENDING_AUTO        = 'MDN-sent-automatically';
    const SENDING_MANUAL      = 'MDN-sent-manually';
    
    const TYPE_PROCESSED      = 'processed';
    const TYPE_FAILED         = 'failed';

    const MODIFIER_ERROR      = 'error';
    const MODIFIER_WARNING    = 'warning';


    public function __construct($data = null, $params = array()){
        // adapter
        if (!($data instanceof AS2Exception) && $data instanceof Exception) $data = new AS2Exception($data->getMessage(), 6);
        // full automatic handling
        if ($data instanceof AS2Exception) {
            $this->setMessage($data->getMessage());
            //$this->setHeaders($data->getHeaders());
            $this->setAttribute('disposition-type', $data->getLevel());
            $this->setAttribute('disposition-modifier', $data->getMessageShort());

            try {$this->setPartnerFrom($params['partner_from']);}
            catch(Exception $e){$this->partner_from = false;}
            try {$this->setPartnerTo($params['partner_to']);}
            catch(Exception $e){$this->partner_to = false;}
        }
        elseif ($data instanceof AS2Request) { // parse response
            $params = array('is_file'      => false,
                            'mimetype'     => 'multipart/report',
                            'partner_from' => $data->getPartnerFrom(),
                            'partner_to'   => $data->getPartnerTo());
            parent::__construct($data->getContent(), $params);

            // check requirements
            if ($this->partner_from->mdn_signed && !$data->isSigned()){
                throw new AS2Exception('MDN from this partner are defined to be signed.', 4);
            }
        }
        elseif ($data instanceof AS2Message){ // standard processed message
            $params['partner_from'] = $data->getPartnerTo();
            $params['partner_to']   = $data->getPartnerFrom();

            parent::__construct(false, $params);
        }
    }

    public function __toString(){
        return $this->getMessage();
    }

    public function setMessage($message){
        $this->message = $message;
    }

    public function getMessage(){
        return $this->message;
    }

    public function setAttribute($key, $value){
        $this->attributes[strtolower($key)] = $value;
    }

    public function getAttribute($key){
        if (isset($this->attributes[strtolower($key)]))
            return $this->attributes[strtolower($key)];
        else
            return null;
    }

    public function getAttributes(){
        return $this->attributes;
    }

    public function encode($message = null){
        // container
        $container = new Horde_MIME_Part('multipart/report', ' ');

        // first part
        $text = new Horde_MIME_Part('text/plain', $this->getMessage(), MIME_DEFAULT_CHARSET, null, '7bit');
        // add human readable message
        $container->addPart($text);

        // second part
        $lines = array();
        $lines['Reporting-UA']          = 'AS2Secure Php Lib';//$this->getAttribute('reporting-ua');
        if ($this->getPartnerFrom()) {
            $lines['Original-Recipient']    = 'rfc822; ' . $this->getPartnerFrom()->id;
            $lines['Final-Recipient']       = 'rfc822; ' . $this->getPartnerFrom()->id;
        }
        $lines['Original-Message-ID']   = $this->getAttribute('original-message-id');
        $lines['Disposition']           = $this->getAttribute('action-mode') . '/' . $this->getAttribute('sending-mode') . '; ' . $this->getAttribute('disposition-type');
        if ($this->getAttribute('disposition-type') != self::TYPE_PROCESSED) $lines['Disposition'] .= ': ' . $this->getAttribute('disposition-modifier');
        if ($this->getAttribute('received-content-mic')) $lines['Received-Content-MIC']  = $this->getAttribute('received-content-mic');

        // build computer readable message
        $content = '';
        foreach($lines as $key => $value)
            $content .= $key . ': ' . $value . "\n";

        $mdn = new Horde_MIME_Part('message/disposition-notification', $content, MIME_DEFAULT_CHARSET, null, '7bit');
        $container->addPart($mdn);

        $this->setMessageId(self::generateMessageID($this->getPartnerFrom()));

        // headers setup
        $headers = array(
             'AS2-Version'                  => '1.0',
             'Message-ID'                   => $this->getMessageId(),
             'Mime-Version'                 => '1.0',
             'Server'                       => 'AS2Secure Php Lib',
             'User-Agent'                   => 'AS2Secure Php Lib',
        );
        $headers = array_merge($container->header(), $headers);

        if ($this->getPartnerFrom()) {
            $headers_from = array(
                 'AS2-From'                     => '"' . $this->getPartnerFrom()->id . '"',
                 'From'                         => $this->getPartnerFrom()->email,
                 'Subject'                      => $this->getPartnerFrom()->mdn_subject,
                 'Disposition-Notification-To'  => $this->getPartnerFrom()->send_url,
            );
            $headers = array_merge($headers, $headers_from);
        }

        if ($this->getPartnerTo()) {
            $headers_to = array(
                 'AS2-To'                       => '"' . $this->getPartnerTo()->id . '"',
                 'Recipient-Address'            => $this->getPartnerTo()->send_url,
            );
            $headers = array_merge($headers, $headers_to);
        }

        if ($message && ($url = $message->getHeader('Receipt-Delivery-Option')) && $this->getPartnerFrom()){
            $this->url = $url;
            $headers['Recipient-Address'] = $this->getPartnerFrom()->send_url;
        }

        $this->headers = new AS2Header($headers);

        $this->path = AS2Adapter::getTempFilename();
        
        // signing if requested
        if ($message && $message->getHeader('Disposition-Notification-Options')) {
            file_put_contents($this->path, $container->toCanonicalString(true));
            $this->path = $this->adapter->sign($this->path);

            $content = file_get_contents($this->path);
            $this->headers->addHeadersFromMessage($content);

            if (strpos($content, "\n\n") !== false) $content = substr($content, strpos($content, "\n\n") + 2);
            file_put_contents($this->path, ltrim($content));
        }
        else {
            file_put_contents($this->path, $container->toCanonicalString(false));
            $content = $container->toString();
        }
    }
    
    public function decode(){
        $params = array('include_bodies' => true,
                        'decode_headers' => true,
                        'decode_bodies'  => true,
                        'input'          => false,
                        'crlf'           => "\n"
                        );
        $decoder = new Mail_mimeDecode($this->getContent());
        $structure = $decoder->decode($params);
        $this->attributes = array();

        foreach($structure->parts as $num => $part)
        {
            if (strtolower($part->headers['content-type']) == 'message/disposition-notification')
            {
                preg_match_all('/([^: ]+): (.+?(?:\r\n\s(?:.+?))*)\r\n/m', $part->body, $headers);
                $headers = array_combine($headers[1], $headers[2]);
                foreach($headers as $key => $val)
                    $this->setAttribute(trim(strtolower($key)), trim($val));
            }
            else
                $this->setMessage(trim($part->body));
        }
    }

    public function getUrl(){
        return $this->url;
    }
}
