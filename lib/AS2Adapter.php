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

class AS2Adapter {
    /**
     * Allow to specify full path to main applications
     * for overriding PATH usage
     */
    public static $sslpath  = 'openssl';
    public static $javapath = 'java';
    
    protected $partner_from = null;
    protected $partner_to   = null;
    
    /**
     * Array to store temporary files created and scheduled to unlink
     */
    protected static $tmp_files = null;
    
    public function __construct($partner_from, $partner_to){
        try {
            $this->partner_from = AS2Partner::getPartner($partner_from);
        }
        catch(Exception $e){
            throw new AS2Exception('Sender AS2 id '.$partner_from.' is unknown.');
        }

        try {
            $this->partner_to   = AS2Partner::getPartner($partner_to);
        }
        catch(Exception $e){
            throw new AS2Exception('Receiver AS2 id '.$partner_to.' is unknown.');
        }
    }
    
    public function compress($mime_part) {
        $input_tmp = self::getTempFilename();
        $output = self::getTempFilename();
        
        try {
            file_put_contents($input_tmp, $mime_part->toString());
            
            // execute main operation
            $command = self::$javapath.' -jar '.escapeshellcmd(AS2_DIR_BIN.'zlib.jar '.escapeshellcmd($input_tmp). ' > '.escapeshellcmd($output).' 2>/dev/null');
            
            $result = self::exec($command);
            
            $message = file_get_contents($output);
            $cmime_part = Horde_MIME_Structure::parseTextMIMEMessage($message);
            
            return $cmime_part;
        }
        catch(Exception $e){
            throw $e;
        }
    }
    
    public function decompress($input) {
        $output = self::getTempFilename();
        
        try {
            $command = self::$javapath.' -jar '.escapeshellcmd(AS2_DIR_BIN.'zlib.jar -d '.escapeshellcmd($input). ' > '.escapeshellcmd($output).' 2>/dev/null');
            
            $result = self::exec($command);
            
            return $output;
        }
        catch(Exception $e) {
            throw $e;
        }
    }
    
    public function sign($mime_part){
        $input_tmp = self::getTempFilename();
        $output = self::getTempFilename();
        
        try {
            file_put_contents($input_tmp, $mime_part->toCanonicalString());
            
            // execute main operation
            $command = self::$sslpath.' smime -sign -inkey '.escapeshellcmd($this->partner_from->sec_private_key).
                                                  ' -signer '.escapeshellcmd($this->partner_from->sec_public_key).
                                                  ' -in '.escapeshellcmd($input_tmp).
                                                  ' -out '.escapeshellcmd($output).
                                                  ' 2>&1';
            $result = self::exec($command);

            /* Break the result into its components */
            $message = file_get_contents($output);
            $mime_message = Horde_MIME_Structure::parseTextMIMEMessage($message);
            
            $smime_sign = $mime_message->getPart(2);
            $smime_sign->setDescription('S/MIME Cryptographic Signature');
            $smime_sign->transferDecodeContents();
            $smime_sign->setTransferEncoding('base64');
    
            $smime_part = new Horde_MIME_Part('multipart/signed');
            $smime_part->setContents('This is a cryptographically signed message in MIME format.' . "\n");
            $smime_part->addPart($mime_part);
            $smime_part->addPart($smime_sign);
            $smime_part->setContentTypeParameter('protocol', 'application/pkcs7-signature');
            $smime_part->setContentTypeParameter('micalg', 'sha1');

            file_put_contents($output, $smime_part->toString());
            //self::fixContentType($output, 'sign');

            //echo 'calc:'.self::calculateMicChecksum($input_tmp)."\n";
            //echo 'sign:'.self::getMicChecksum($output)."\n";

            if (self::calculateMicChecksum($input_tmp) != self::getMicChecksum($output)){
                throw new AS2Exception('An unexpected error occurs while signing AS2 Message.');
            }
    
            return $smime_part;
        }
        catch(Exception $e){
            throw $e;
        }
    }

    public function verify($input){
        try {
            // clear error buffer
            while($err = openssl_error_string());

            // usefull in case of self-signed certificates
            $cafile = ($this->partner_from->sec_trusted_certificates?$this->partner_from->sec_trusted_certificates:$this->partner_from->sec_public_key);

            // execute main operation
            $command = self::$sslpath.' smime -verify -nointern '.
                                                    ' -certfile '.escapeshellcmd($this->partner_from->sec_public_key).
                                                    ' -CAfile '.escapeshellcmd($cafile).
                                                    ' -in '.escapeshellcmd($input).
                                                    ' -out /dev/null'.
                                                    ' 2>&1';
            // on error, an exception is throw
            $result = self::exec($command);

            return true;
        }
        catch(Exception $e){
            try {
                // clear error buffer
                while($err = openssl_error_string());

                // execute minimal verification
                $result = openssl_pkcs7_verify($input, PKCS7_NOVERIFY, '/dev/null');

                // handle differents errors
                if ($result === true)
                    throw new AS2Exception('The signing certificate is invalid');
                if ($result === false)
                    throw new AS2Exception('The message has been tampered');

                // handle general error
                throw new AS2Exception(openssl_error_string());
            }
            catch(Exception $e){
                throw $e;
            }
        }
    }

    public function extract($input){
        $output = self::getTempFilename();

        try {
            // usefull in case of self-signed certificates
            $cafile = ($this->partner_from->sec_trusted_certificates?$this->partner_from->sec_trusted_certificates:$this->partner_from->sec_public_key);

            // content extraction is only available with openssl command line
            $command = self::$sslpath.' smime -verify -nointern '.
                                                    ' -certfile '.escapeshellcmd($this->partner_from->sec_public_key).
                                                    ' -CAfile '.escapeshellcmd($cafile).
                                                    ' -in '.escapeshellcmd($input).
                                                    ' -out '.escapeshellcmd($output).
                                                    ' 2>&1';
            $result = self::exec($command);

            return $output;
        }
        catch(Exception $e){
            throw $e;
        }
    }

    /**
     * Encrypt a mimepart
     *
     * @param mime_part $mime_part      The mimepart to encrypt
     * @param string    $cypher         The Cypher to use for encryption
     *
     * @return mime_part                The mimepart message encrypted
     *
     */
    public function encrypt($mime_part, $cypher = 'des3'){
        $input_tmp = self::getTempFilename();
        $output = self::getTempFilename();

        try {
            file_put_contents($input_tmp, $mime_part->toString());

            $command = self::$sslpath.' smime -encrypt -in '.escapeshellcmd($input_tmp).' -out '.escapeshellcmd($output).' -'.$cypher.' '.escapeshellcmd($this->partner_to->sec_public_key).' 2>&1';
            $result = $this->exec($command);

            $message = file_get_contents($output);
            $cmime_part = Horde_MIME_Structure::parseTextMIMEMessage($message);
        }
        catch(Exception $e){
            throw $e;
        }
        return $cmime_part;
    }

    /**
     * Decrypt a message
     * 
     * @param string $input          The file to decrypt
     *
     * @return string                The file decrypted
     */
    public function decrypt($input){
        $output = self::getTempFilename();

        try {
            $command = self::$sslpath.' smime -decrypt -in '.escapeshellcmd($input).' -inkey '.escapeshellcmd($this->partner_to->sec_private_key).' -des3 -out '.escapeshellcmd($output).' 2>&1';
            $result = $this->exec($command);

            return $output;
        }
        catch(Exception $e){
            throw $e;
        }
    }

    /**
     * Calculate the message integrity check (MIC) using SHA1 or MD5 algo
     *
     * @param string $input          The file to use
     * @param string $algo           The algo to use
     *
     * @return string                The hash calculated
     */
    public static function calculateMicChecksum($input, $algo = 'sha1'){
        if (strtolower($algo) == 'sha1')
            return base64_encode(self::hex2bin(sha1_file($input))).', sha1';
        else
            return base64_encode(self::hex2bin(md5_file($input))).', md5';
    }
    
    /**
     * Extract the message integrity check (MIC) from the digital signature
     *
     * @param string $input          The file containing the signed message
     *
     * @return string                The hash extracted
     */
    public static function getMicChecksum($input)
    {
        try {
            $command = self::$sslpath.' smime -pk7out -in '.escapeshellcmd($input).' | '.self::$sslpath.' asn1parse';
            $dump = self::exec($command, true);

            $command = self::$sslpath.' smime -pk7out -in '.escapeshellcmd($input).' | '.self::$sslpath.' asn1parse | grep -C2 -i messageDigest | tail -n1';
            $dump = self::exec($command, true);
            $dump = substr($dump[0], strrpos($dump[0], ':')+1);
             /**
              * TODO : obtain real mic algo
              */
            return base64_encode(self::hex2bin($dump)).', sha1';
        }
        catch(Exception $e) {
            return false;
        }
    }
    
    /**
     * Extract Private Certificate from a PKCS12 Certificate
     *
     * @param string $input          The PKCS12 Certificate
     * @param string $password       The PKCS12 Certificate's password
     * @param string $new_password   The new password to use for the new private key
     *
     * @return string                The file which contains the Private Certificate
     */
    public static function getPrivateFromPKCS12($input, $password = '', $new_password = ''){
        $output = self::getTempFilename();
        
        try {
            $command = self::$sslpath.' pkcs12 -in '.escapeshellcmd($input).' -out '.escapeshellcmd($output).' -nocerts';
            if ($password){
                $command .= ' -passin stdin';
                if ($new_password){
                    $command .= ' -passout stdin > /dev/null 2>&1';
                }
                else{
                    $command .= ' -nodes > /dev/null 2>&1';
                }
                $handle = popen($command, 'w');
                fwrite($handle, $password."\n");
                if ($new_password){
                    fwrite($handle, $new_password."\n");
                }
                pclose($handle);
            }
            else {
                $command .= ' -nodes > /dev/null 2>&1';
                self::exec($command);
            }

            if (file_get_contents($output) == ''){
                throw new AS2Exception('Unexpected error while extracting certificates from pkcs12 container');
            }
            
            return $output;
        }
        catch(Exception $e){
            return false;
        }
    }
    
    /**
     * Extract Public certificate from a PKCS12 Certificate
     *
     * @param string $input      The PKCS12 Certificate
     * @param string $password   The PKCS12 Certificate's password
     *
     * @return string            The file which contains the Public Certificate
     */
    public static function getPublicFromPKCS12($input, $password = ''){
        $output = self::getTempFilename();
        
        try {
            $command = self::$sslpath.' pkcs12 -in '.escapeshellcmd($input).' -out '.escapeshellcmd($output).' -nokeys -clcerts';
            if ($password){
                $command .= ' -passin stdin > /dev/null 2>&1';
                
                $handle = popen($command, 'w');
                fwrite($handle, $password."\n");
                pclose($handle);
            }
            else {
                $command .= ' > /dev/null 2>&1';
                self::exec($command);
            }
                
            if (file_get_contents($output) == ''){
                throw new AS2Exception('Unexpected error while extracting certificates from pkcs12 container');
            }
            
            return $output;
        }
        catch(Exception $e){
            return false;
        }
    }
    
    /**
     * Extract CA from a PKCS12 Certificate
     *
     * @param string $input      The PKCS12 Certificate
     * @param string $password   The PKCS12 Certificate's password
     *
     * @return string            The file which contains the CA
     */
    public static function getCAFromPKCS12($input, $password = ''){
        $output = self::getTempFilename();
        
        try {
            $command = self::$sslpath.' pkcs12 -in '.escapeshellcmd($input).' -out '.escapeshellcmd($output).' -nokeys -cacerts';
            if ($password){
                $command .= ' -passin stdin > /dev/null 2>&1';
                
                $handle = popen($command, 'w');
                fwrite($handle, $password."\n");
                pclose($handle);
            }
            else {
                $command .= ' > /dev/null 2>&1';
                self::exec($command);
            }
                
            if (file_get_contents($output) == ''){
                throw new AS2Exception('Unexpected error while extracting certificates from pkcs12 container');
            }
            
            return $output;
        }
        catch(Exception $e){
            return false;
        }
    }
    
    /**
     * Create a temporary file into temporary directory and add it to
     * the garbage collector at shutdown
     *
     * @return string       The temporary file generated
     */
    public static function getTempFilename(){
        if (is_null(self::$tmp_files)){
            self::$tmp_files = array();
            register_shutdown_function(array("AS2Adapter", "_deleteTempFiles"));
        }
        
        $dir = sys_get_temp_dir();
        $filename = tempnam($dir, 'as2file_');
        self::$tmp_files[] = $filename;
        return $filename;
    }
    
    /**
     * Garbage collector to delete temp files created with 'self::getTempFilename' 
     * with shutdown function
     *
     */
    public static function _deleteTempFiles(){
        foreach(self::$tmp_files as $file)
            @unlink($file);
    }

    /**
     * Execute a command line and throw Exception if an error appends
     * 
     * @param string $command            The command line to execute
     * @param boolean $return_output     True  to return all data from standard output
     *                                   False to return only the error code
     *
     * @return string    The error code or the content from standard output
     */
    public static function exec($command, $return_output = false){
        $output = array();
        $return_var = 0;
        try{
            exec($command, $output, $return_var);
            $line = (isset($output[0])?$output[0]:'Unexpected error in command line : '.$command);
            if ($return_var) throw new Exception($line, (int)$return_var);
        }
        catch(Exception $e){
            throw $e;
        }
        
        if ($return_output)
            return $output;
        else
            return $return_var;
    }

    /**
     * Fix the content type to match with RFC 2311
     *
     * @param string $file  The file to fix
     * @param string $type  The type to choose to correct (crypt | sign)
     *
     * @return none
     */
    protected static function fixContentType($file, $type) {
        if ($type == 'crypt') {
            $from = 'application/x-pkcs7-mime';
            $to = 'application/pkcs7-mime';
        } else {
            $from = 'application/x-pkcs7-signature';
            $to = 'application/pkcs7-signature';
        }
        $content = file_get_contents($file);
        $content = str_replace('Content-Type: ' . $from, 'Content-Type: ' . $to, $content);
        file_put_contents($file, $content);
    }
    
    /**
     * Convert a string from hexadecimal format to binary format
     *
     * @param string $str   The string in hexadecimal format.
     *
     * @return string       The string in binary format.
     */
    public static function hex2bin($str) {
        $bin = '';
        $i = 0;
        do {
            $bin .= chr(hexdec($str{$i}.$str{($i + 1)}));
            $i += 2;
        } while ($i < strlen($str));
        return $bin;
    }
    
    /**
     * Determine the mimetype of a file (also called 'Content-Type')
     *
     * @param string $file  The file to analyse
     *
     * @return string       The mimetype
     */
    public static function detectMimeType($file) {
        // for old PHP (deprecated)
        if (function_exists('mime_content_type'))
            return mime_content_type($file);

        // for PHP > 5.3.0 / PECL FileInfo > 0.1.0
        if (function_exists('finfo_file')){
            $finfo = finfo_open(FILEINFO_MIME);
            $mimetype = finfo_file($finfo, $file);
            finfo_close($finfo);
            return $mimetype;
        }

        $os = self::detectOS();
        // for Unix OS : command line
        if ($os == 'UNIX') {
            $mimetype = trim(exec('file -b -i '.escapeshellarg($file)));
            $parts = explode(';', $mimetype);
            return trim($parts[0]);
        }
        
        // fallback for Windows and Others OS
        // source code found at : 
        // @link http://fr2.php.net/manual/en/function.mime-content-type.php#87856
        $mime_types = array(
            'txt' => 'text/plain',
            'htm' => 'text/html',
            'html' => 'text/html',
            'php' => 'text/html',
            'css' => 'text/css',
            'js' => 'application/javascript',
            'json' => 'application/json',
            'xml' => 'application/xml',
            'swf' => 'application/x-shockwave-flash',
            'flv' => 'video/x-flv',

            // images
            'png' => 'image/png',
            'jpe' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'jpg' => 'image/jpeg',
            'gif' => 'image/gif',
            'bmp' => 'image/bmp',
            'ico' => 'image/vnd.microsoft.icon',
            'tiff' => 'image/tiff',
            'tif' => 'image/tiff',
            'svg' => 'image/svg+xml',
            'svgz' => 'image/svg+xml',

            // archives
            'zip' => 'application/zip',
            'rar' => 'application/x-rar-compressed',
            'exe' => 'application/x-msdownload',
            'msi' => 'application/x-msdownload',
            'cab' => 'application/vnd.ms-cab-compressed',

            // audio/video
            'mp3' => 'audio/mpeg',
            'qt' => 'video/quicktime',
            'mov' => 'video/quicktime',

            // adobe
            'pdf' => 'application/pdf',
            'psd' => 'image/vnd.adobe.photoshop',
            'ai' => 'application/postscript',
            'eps' => 'application/postscript',
            'ps' => 'application/postscript',

            // ms office
            'doc' => 'application/msword',
            'rtf' => 'application/rtf',
            'xls' => 'application/vnd.ms-excel',
            'ppt' => 'application/vnd.ms-powerpoint',

            // open office
            'odt' => 'application/vnd.oasis.opendocument.text',
            'ods' => 'application/vnd.oasis.opendocument.spreadsheet',
        );

        $ext = strtolower(array_pop(explode('.',$filename)));
        if (array_key_exists($ext, $mime_types)) {
            return $mime_types[$ext];
        }
        else {
            return 'application/octet-stream';
        }
    }

    /**
     * Determinate the Server OS
     *
     * @return string    The OS : WIN | UNIX | OTHER
     *
     */
    public static function detectOS() {
        $os = php_uname('s');
        if (stripos($os, 'win') !== false) return 'WIN';
        if (stripos($os, 'linux') !== false || stripos($os, 'unix') !== false) return 'UNIX';
        return 'OTHER';
    }
}

