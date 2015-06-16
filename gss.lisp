;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:ntlm)

;; this file provides a GSS API for NTLM 

(defclass ntlm-credentials ()
  ())

(defvar *current-user* nil)

(defmethod glass:acquire-credentials ((type (eql :ntlm)) principal &key)
  (declare (ignore principal))
  (unless *current-user* (error 'glass:gss-error :major :no-cred))
  (make-instance 'ntlm-credentials))

(defvar *default-flags* '(:NEGOTIATE-UNICODE
                            :NEGOTIATE-OEM :REQUEST-TARGET
                            :NEGOTIATE-NTLM
                            :NEGOTIATE-OEM-DOMAIN-SUPPLIED
                            :NEGOTIATE-OEM-WORKSTATION-SUPPLIED
                            :NEGOTIATE-ALWAYS-SIGN
                            :NEGOTIATE-EXTENDED-SESSIONSECURITY
                            :NEGOTIATE-VERSION :NEGOTIATE-128
                            :NEGOTIATE-56))

(defstruct ntlm 
  user domain password-md4)
        
(defclass ntlm-context ()
  ((user :initarg :user :initform nil :reader ntlm-context-user)
   (domain :initarg :domain :initform nil :reader ntlm-context-domain)
   (challenge :initarg :challenge :initform nil :reader ntlm-context-server-challenge)))

(defmethod glass:initialize-security-context ((creds ntlm-credentials) &key)
  (values (make-instance 'ntlm-context)
          (pack-negotiate-message *default-flags* 
                                  :workstation (machine-instance)
                                  :domain (ntlm-domain *current-user*)
                                  :version (make-ntlm-version 6 1 1))
	  t))

(defmethod glass:initialize-security-context ((context ntlm-context) &key buffer)
  ;; we have received a CHALLENGE message, generate an AUTHENTICATE response
  (let* ((username (ntlm-user *current-user*))
         (domain (ntlm-domain *current-user*))
         (password-md4 (ntlm-password-md4 *current-user*))
         (challenge (unpack-challenge-message buffer))
         (lmowf (lmowf-v2 username domain password-md4))
         (ntowf (ntowf-v2 username domain password-md4))
         (server-challenge (cdr (assoc :server-challenge challenge)))
         (client-challenge (client-challenge))
         (time (cdr (assoc :timestamp (cdr (assoc :target-info challenge)))))
         (target-info-buffer (cdr (assoc :target-info-buffer challenge)))
         (temp (make-temp time client-challenge target-info-buffer))
         (lm-response (lm-response-v2 lmowf server-challenge client-challenge))
         (nt-response (nt-response-v2 ntowf
                                      server-challenge
                                      temp))
         (session-base-key (session-base-key-v2 ntowf 
                                                server-challenge
                                                temp))
         (key-exchange-key (key-exchange-key session-base-key
                                             lm-response
                                             server-challenge
                                             lmowf))
         (exported-session-key (exported-session-key :negotiate-key-exch t
                                                     :key-exchange-key key-exchange-key)))
    
      (values (make-instance 'ntlm-context :challenge challenge)
              (pack-authenticate-message 
               *default-flags*
               :lm-response lm-response
               :nt-response nt-response 
               :domain domain
               :username username
               :workstation (machine-instance)
               :version (make-ntlm-version 6 1 1)
               :encrypted-session-key (encrypted-session-key key-exchange-key exported-session-key))
	      nil)))


(defmethod glass:accept-security-context ((creds ntlm-credentials) buffer &key)
  ;; the buffer is an initial NEGOTIATE message
  (let ((neg (unpack-negotiate-message buffer))
        (challenge (server-challenge)))
    (declare (ignore neg))
    ;; generate a challenge message
    (values (make-instance 'ntlm-context
                           :challenge challenge)
            (pack-challenge-message *default-flags*
                                    challenge
                                    :target-name (machine-instance)
                                    :version (make-ntlm-version 6 1 1)
                                    :target-info 
                                    (make-target-info :nb-domain-name (ntlm-domain *current-user*)
                                                      :nb-computer-name (machine-instance)
                                                      :timestamp (filetime)))
	    t)))

(defun logon-user (username password &optional domain)
  "Logon the current user using the USERNAME and PASSWORD." 
  (declare (type string username password)
           (type (or string null) domain))
  (open-ntlm-database)
  (setf *current-user*
        (make-ntlm :user username
                   :password-md4 (password-md4 password)
                   :domain domain))
  nil)

;; ------------------------

(defun user-password-md4 (username)
  (declare (type string username))
  (let ((password (find-ntlm-user username)))
    (if password
        (password-md4 password)
        (error "User ~S not found" username))))

(defun authenticate (buffer server-challenge username domain)
  (let ((nt-response (nt-response-v2-list buffer))
        (password-md4 (user-password-md4 username)))
    (when password-md4
      (let ((client-response (cdr (assoc :nt-response nt-response)))
            (server-response (subseq (nt-response-v2 (ntowf-v2 username domain password-md4)
                                                     server-challenge
                                                     (cdr (assoc :temp-buffer nt-response)))
                                     0 16)))
        (every #'= client-response server-response)))))

(defmethod glass:accept-security-context ((context ntlm-context) buffer &key)
  ;; the buffer is an AUTHENTICATE message, validate the user against the local database 
  (let ((amsg (unpack-authenticate-message buffer)))
    (if (authenticate (cdr (assoc :nt-response amsg))
		      (ntlm-context-server-challenge context)
		      (cdr (assoc :username amsg))
		      (cdr (assoc :domain amsg)))
	(values (make-instance 'ntlm-context
			       :user (cdr (assoc :username amsg))
			       :domain (cdr (assoc :domain amsg)))
		nil
		nil)
	(error 'glass:gss-error :major :defective-credential))))

(defmethod glass:context-principal-name ((context ntlm-context) &key)
  (format nil "~A@~A" (ntlm-context-user context) (ntlm-context-domain context)))


;; --------------------------------

;; TODO: how to do the GSS mic/wrap functions for ntlm?
