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
 * @version 0.7.2
 * 
 */

class AS2Message extends AS2Abstract {
    
    protected $mic_checksum = false;
    
    public function __construct($data, $params = array()) {
        parent::__construct($data, $params);

        if ($data instanceof AS2Request){
            $this->path = $data->getPath();
        }
        elseif ($data instanceof Horde_MIME_Part){
            $this->path = AS2Adapter::getTempFilename();
            file_put_contents($this->path, $data->toString(true));
        }
        elseif ($data){
            if (!isset($params['is_file']) || $params['is_file'])
                $this->addFile($data, '', '', true);
            else
                $this->addFile($data, '', '', false);
        }

        if (isset($params['mic'])){
            $this->mic_checksum = $params['mic'];
        }
    }

    public function addFile($data, $mimetype = '', $filename = '', $is_file = true, $encoding = ''){
        if (!$is_file){
            $file    = AS2Adapter::getTempFilename();
            file_put_contents($file, $data);
            $data    = $file;
            $is_file = true;
        }
        else{
            if (!$filename) $filename = basename($data);
        }

        if (!$mimetype) $mimetype = AS2Adapter::detectMimeType($data);

        $this->files[] = array('path'     => $data,
                               'mimetype' => $mimetype,
                               'filename' => $filename,
                               'encoding' => $encoding);
        return true;
    }

    public function getFiles(){
        return $this->files;
    }
    
    public function getMicChecksum() {
        return $this->mic_checksum;
    }
    
    public function getUrl() {
        return $this->getPartnerTo()->send_url;
    }
    
    public function getAuthentication() {
        return array('method'   => $this->getPartnerTo()->send_credencial_method,
                     'login'    => $this->getPartnerTo()->send_credencial_login,
                     'password' => $this->getPartnerTo()->send_credencial_password);
    }
    
    public function encode() {
        if (!$this->getPartnerFrom() instanceof AS2Partner || !$this->getPartnerTo() instanceof AS2Partner)
            throw new AS2Exception('Object not properly initialized');
        
        // initialisation
        $this->mic_checksum = false;
        $this->setMessageId(self::generateMessageID($this->getPartnerFrom()));

        // chargement et construction du message
        $files = $this->getFiles();
        
        // initial message creation : mime_part
        try {
            // managing all files (parts)
            $parts = array();
            foreach($files as $file){
                $mime_part = new Horde_MIME_Part($file['mimetype']);
                $mime_part->setContents(file_get_contents($file['path']));
                $mime_part->setName($file['filename']);

                $parts[] = $mime_part;
            }
            if (count($parts) > 1){
                // handling multipart file
                $mime_part = new Horde_MIME_Part('multipart/mixed');
                foreach($parts as $part)
                    $mime_part->addPart($part);
            }
            else{
                // handling mono part (body)
                $mime_part = $parts[0];
            }
        }
        catch(Exception $e) {
            throw $e;
            return false;
        }
        
        // signing file if wanted by Partner_To
        if ($this->getPartnerTo()->sec_signature_algorithm != AS2Partner::SIGN_NONE) {
            try {
                $mime_part = $this->adapter->sign($mime_part);
                $this->is_signed = true;
                $mic_tmp = AS2Adapter::getTempFilename();
                file_put_contents($mic_tmp, $mime_part->toString());
                $this->mic_checksum = AS2Adapter::getMicChecksum($mic_tmp);
            }
            catch(Exception $e) {
                throw $e;
                return false;
            }
        }

        // crypting file if wanted by Partner_To
        if ($this->getPartnerTo()->sec_encrypt_algorithm   != AS2Partner::CRYPT_NONE) {
            try {
                $mime_part = $this->adapter->encrypt($mime_part);
                $this->is_crypted = true;
            }
            catch(Exception $e) {
                throw $e;
                return false;
            }
        }

        $this->path = AS2Adapter::getTempFilename();
        if ($mime_part->getTransferEncoding() == 'base64'){
            file_put_contents($this->path, base64_decode($mime_part->toString(false)));
        }
        else{
            file_put_contents($this->path, $mime_part->toString());
        }

        // headers setup
        $headers = array(
             'AS2-From'                     => $this->getPartnerFrom()->id,
             'AS2-To'                       => $this->getPartnerTo()->id,
             'AS2-Version'                  => '1.0',
             'From'                         => $this->getPartnerFrom()->email,
             'Subject'                      => $this->getPartnerFrom()->send_subject,
             'Message-ID'                   => $this->getMessageId(),
             'Mime-Version'                 => '1.0',
             'Disposition-Notification-To'  => $this->getPartnerFrom()->send_url,
             'Recipient-Address'            => $this->getPartnerTo()->send_url,
             'User-Agent'                   => 'AS2Secure Php Lib',
        );
        
        if ($this->getPartnerTo()->mdn_signed) {
            $headers['Disposition-Notification-Options'] = 'signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha1';
        }
        
        if ($this->getPartnerTo()->mdn_request == AS2Partner::ACK_ASYNC) {
            $headers['Receipt-Delivery-Option'] = $this->getPartnerFrom()->send_url;
        }
        
        if ($this->is_crypted) {
            $headers['Content-Type']         = 'application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m';
            $headers['Content-Disposition'] = 'attachment; filename="smime.p7m"';
        }
        elseif ($this->is_signed) {
            $headers['Content-Type']         = 'multipart/signed; protocol="application/pkcs7-signature"; micalg=sha1';
            $headers['Content-Disposition'] = 'attachment; filename="smime.p7m"';
        }
        else {
            // allowed ???
        }
        $this->headers = $headers;
        
        return true;
    }
    
    public function decode() {
        $this->files = array();
        
        $content = file_get_contents($this->getPath());
        $params = array('include_bodies' => true,
                        'decode_bodies'  => true,
                        'decode_headers' => true);
        $decoder = new Mail_mimeDecode($content);
        $structure = $decoder->decode($params);
        
        if (strtolower($structure->ctype_primary) == 'multipart'){
            foreach($structure->parts as $index => $part){
                $tmp = AS2Adapter::getTempFilename();
                file_put_contents($tmp, $part->body);
                $this->files[] = array('path'     => $tmp,
                                       'filename' => $part->ctype_parameters['name'],
                                       'mimetype' => $part->ctype_primary.'/'.$part->ctype_secondary);
                //echo $part->ctype_parameters['name']."\n";
                //echo strlen($part->body)."\n";
            }
        }
        else {
            $tmp = AS2Adapter::getTempFilename();
            file_put_contents($tmp, $structure->body);
            $this->files[] = array('path'     => $tmp,
                                   'filename' => $structure->ctype_parameters['name'],
                                   'mimetype' => $structure->ctype_primary.'/'.$structure->ctype_secondary);
        }

        //echo 'nb payloads : '.count($this->files);
    }
    
    public function generateMDN($exception = null) {
        $mdn = new AS2MDN($this);

        $message_id = $this->getHeader('message-id');
        $partner    = $this->getPartnerTo()->id;
        $mic        = $this->getMicChecksum();

        $mdn->setAttribute('Reporting-UA', 'AS2Secure Php Lib');
        $mdn->setAttribute('Original-Recipient', 'rfc822; '.$partner);
        $mdn->setAttribute('Final-Recipient', 'rfc822; '.$partner);
        $mdn->setAttribute('Original-Message-ID', $message_id);
        if ($mic)
            $mdn->setAttribute('Received-Content-MIC', $mic);

        if (is_null($exception)){
            $mdn->setMessage('The AS2 message has been received.');
            $mdn->setAttribute('Disposition-Type', 'processed');
        }
        else {
            if (!$exception instanceof AS2Exception)
                $exception = new AS2Exception($exception->getMessage());

            $mdn->setMessage($exception->getMessage());
            $mdn->setAttribute('Disposition-Type', 'failure');
            $mdn->setAttribute('Disposition-Modifier', $exception->getLevel().': '.$exception->getMessageShort());
        }

        return $mdn;
    }
}
