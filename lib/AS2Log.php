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

class AS2Log {
    protected static $stack = array();
    protected static $filename = 'events.log';
    
    const INFO    = 'info';
    const ERROR   = 'error';
    const WARNING = 'warning';
    const FAILURE = 'failure';
    
    protected static $current_message_id = '';

    protected $message_id = '';
    protected $message = '';
    protected $code = 0;
    protected $level = self::INFO;
    
    protected function __construct($message, $code = 0, $level = self::INFO){
        $this->message_id = self::$current_message_id;
        $this->message = $message;
        $this->code = $code;
        $this->level = $level;

        $this->logEvent();
    }

    protected function logEvent(){
        umask(000);
        if (!file_exists(AS2_DIR_LOGS))
            mkdir(AS2_DIR_LOGS, 0777, true);
        $message = '['.date('Y-m-d H:i:s').'] '.trim($this->message_id, '<>').' : ('.strtoupper($this->level).') '.$this->message."\n";
        //$message = '['.date('Y-m-d H:i:s').'] ('.strtoupper($this->level).') '.$this->message."\n";
        file_put_contents(AS2_DIR_LOGS.self::$filename, $message, FILE_APPEND);
    }
    
    public function getMessageId(){
        return self::$current_message_id;
    }
    
    public function getMessage(){
        return $this->message;
    }
    
    public function getCode(){
        return $this->code;
    }
    
    public function getLevel(){
        return $this->level;
    }
    
    public static function info($message_id, $message, $code = 0){
        if ($message_id) self::$current_message_id = $message_id;
        $error = new self($message, $code, self::INFO);
        self::$stack[] = $error;
    }
    
    public static function warning($message_id, $message, $code = 0){
        if ($message_id) self::$current_message_id = $message_id;
        $error = new self($message, $code, self::WARNING);
        self::$stack[] = $error;
    }
    
    public static function error($message_id, $message, $code = 0){
        if ($message_id) self::$current_message_id = $message_id;
        $error = new self($message, $code, self::ERROR);
        self::$stack[] = $error;
    }
    
    public static function getStack($level = null){
        if ($level){
            $tmp = array();
            foreach(self::$stack as $event)
                if ($event->level == $event)
                    $tmp[] = $event;
            return $tmp;
        }
        return self::$stack;
    }
    
    public static function getCount($level = null){
        return count(self::getStack($level));
    }
    
    public static function hasError(){
        foreach(self::$stack as $event)
            if ($event->level == self::ERROR)
                return true;
        return false;
    }
    
    public static function getLastLogEvents($count = 40, $reverse = true) {
        // build command line
        $command = 'cat -n '.escapeshellcmd(AS2_DIR_LOGS.self::$filename);
        if ($reverse) $command .= ' | tail -n '.escapeshellcmd($count).' | sort -r | cut -f2-20';
        
        // exec command line
        $logs = AS2Adapter::exec($command, true);
        
        // return logs
        return $logs;
    }
}
