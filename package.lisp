;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

;;;; NTLM Authentication library

;;; 
;;; Provides functions and data structures to handle the NTLM authentication protocol,
;;; commonly used by Microsoft Windows platforms.
;;; See http://msdn.microsoft.com/en-gb/library/cc236621.aspx for more information.
;;;
;;; Copyright (C) Frank James, July 2014
;;;



(defpackage #:ntlm 
  (:use #:cl #:packet)
  (:export	   
	   ;; #:pack-negotiate-message
	   ;; #:unpack-negotiate-message
	   ;; #:pack-challenge-message
	   ;; #:unpack-challenge-message
	   ;; #:pack-authenticate-message
	   ;; #:unpack-authenticate-message

	   ;; #:make-ntlm-version
	   ;; #:make-target-info
       ;; #:make-single-host

	   ;; #:des
	   ;; #:desl
	   ;; #:md4
	   ;; #:md5
	   ;; #:crc32
       ;; #:rc4-init
	   ;; #:rc4
       ;; #:rc4k
	   ;; #:hmac-md5
	   ;; #:lmowf-v1
	   ;; #:ntowf-v1
	   ;; #:ntowf-v2
	   ;; #:lmowf-v2
	   ;; #:session-base-key-v1
	   ;; #:session-base-key-v2
	   ;; #:key-exchange-key
       ;; #:make-temp
	   ;; #:lm-response-v1
	   ;; #:nt-response-v1
	   ;; #:lm-response-v1*
	   ;; #:nt-response-v1*
	   ;; #:lm-response-v2
	   ;; #:nt-response-v2
       ;; #:nt-response-v2-list
	   ;; #:sign-key
	   ;; #:seal-key
	   ;; #:mac
	   ;; #:encrypted-session-key
	   ;; #:password-md4
       ;; #:mic
       ;; #:client-challenge
       ;; #:server-challenge
       ;; #:nonce
       ;; #:exported-session-key
       ;; #:unix
       ;; #:filetime
       ;; #:filetime-unix

       ;; new GSS interface
       #:logon-user
       #:find-ntlm-user
       #:remove-ntlm-user
       #:add-ntlm-user
       #:list-ntlm-users
       #:open-ntlm-database
       #:close-ntlm-database
       #:*ntlm-database-path*

       ))





