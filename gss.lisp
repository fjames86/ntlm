;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(in-package #:ntlm)

;; this file provides a GSS API for NTLM 

(defclass ntlm-credentials ()
  ())

(defvar *default-ntlm-values* nil)

(defmethod glass:acquire-credentials ((type (eql :ntlm)) principal &key)
  (declare (ignore principal))
  (unless *default-ntlm-values* (error 'glass:gss-error :major :no-cred))
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
  user domain password)
        
(defclass ntlm-context ()
  ((user :initarg :user :initform nil :reader ntlm-context-user)
   (domain :initarg :domain :initform nil :reader ntlm-context-domain)
   (challenge :initarg :challenge :initform nil :reader ntlm-context-server-challenge)))

(defmethod glass:initialize-security-context ((creds ntlm-credentials) &key)
  (values (make-instance 'ntlm-context)
          (pack-negotiate-message *default-flags* 
                                  :workstation (machine-instance)
                                  :domain (ntlm-domain *default-ntlm-values*)
                                  :version (make-ntlm-version 6 1 1))))

(defmethod glass:initialize-security-context ((context ntlm-context) &key buffer)
  ;; we have received a CHALLENGE message, generate an AUTHENTICATE response
  (let* ((username (ntlm-user *default-ntlm-values*))
         (domain (ntlm-domain *default-ntlm-values*))
         (password-md4 (ntlm-password *default-ntlm-values*))
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
               :encrypted-session-key (encrypted-session-key key-exchange-key exported-session-key)))))


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
                                    (make-target-info :nb-domain-name (ntlm-domain *default-ntlm-values*)
                                                      :nb-computer-name (machine-instance)
                                                      :timestamp (filetime))))))



;; ------------------------
;; password database
(defvar *ntlm-password-path* (merge-pathnames "ntlm.dat" (user-homedir-pathname)))
(defvar *ntlm-mapping* nil)
(defvar *ntlm-stream* nil)
(defconstant +ntlm-block-size+ 128)

(defun database-count ()
  (file-position *ntlm-stream* 0)
  (nibbles:read-ub32/be *ntlm-stream*))

(defun close-ntlm-database ()
  (when *ntlm-mapping*
    (pounds:close-mapping *ntlm-mapping*)
    (setf *ntlm-mapping* nil
          *ntlm-stream* nil)))

(defun open-ntlm-database (&optional (count 32))
  (unless *ntlm-mapping* 
    (setf *ntlm-mapping* (pounds:open-mapping *ntlm-password-path* (* count +ntlm-block-size+))
          *ntlm-stream* (pounds:make-mapping-stream *ntlm-mapping*))
    (let ((real-count (database-count)))
      (cond
        ((zerop real-count)
         ;; new mapping, write count
         (file-position *ntlm-stream* 0)
         (nibbles:write-ub32/be count *ntlm-stream*))
        ((> real-count count)
         ;; mapping is really bigger, remap
         (close-ntlm-database)
         (open-ntlm-database real-count))
        ((< real-count count)
         ;; write the new count
         (file-position *ntlm-stream* 0)
         (nibbles:write-ub32/be count *ntlm-stream*))))))

;; layout of each block:
;; <boolean 4-bytes> <username 32 bytes> <password 32 bytes> <spare 60>
(defstruct ntlm-entry 
  active user password)

(defun read-ntlm-entry (stream)
  (let ((offset (file-position stream))
        (entry (make-ntlm-entry :active (not (zerop (nibbles:read-ub32/be stream))))))
    (let* ((count (nibbles:read-ub32/be stream))
           (buff (nibbles:make-octet-vector count)))
      (read-sequence buff stream)
      (setf (ntlm-entry-user entry) (babel:octets-to-string buff)))
    (file-position stream (+ offset 4 32))
    (let* ((count (nibbles:read-ub32/be stream))
           (buff (nibbles:make-octet-vector count)))
      (read-sequence buff stream)
      (setf (ntlm-entry-password entry) (babel:octets-to-string buff)))
    entry))

(defun write-ntlm-entry (stream entry)
  (let ((offset (file-position stream)))
    (nibbles:write-ub32/be 1 stream)
    (let ((octets (babel:string-to-octets (ntlm-entry-user entry))))
      (nibbles:write-ub32/be (length octets) stream)
      (write-sequence octets stream))
    (file-position stream (+ offset 4 32))
    (let ((octets (babel:string-to-octets (ntlm-entry-password entry))))
      (nibbles:write-ub32/be (length octets) stream)
      (write-sequence octets stream))))

(defun add-ntlm-user (username password)
  "Add a new entry into the local database."
  (open-ntlm-database)
  ;; walk the list until we find an unused entry 
  (let (count)
    (pounds:with-locked-mapping (*ntlm-stream*)
      (setf count (database-count))
      (do ((i 1 (1+ i)))
          ((>= i count))
        (let ((offset (file-position *ntlm-stream*))
              (entry (read-ntlm-entry *ntlm-stream*)))
          (cond 
            ((and (ntlm-entry-active entry) 
                  (string= (ntlm-entry-user entry) username))
             (file-position *ntlm-stream* offset)
             (write-ntlm-entry *ntlm-stream* 
                               (make-ntlm-entry :active t 
                                                :user username 
                                                :password password))
             (return-from add-ntlm-user nil))
            ((not (ntlm-entry-active entry))
             ;; free entry, write here
             (file-position *ntlm-stream* offset)
             (write-ntlm-entry *ntlm-stream* 
                               (make-ntlm-entry :active t 
                                                :user username 
                                                :password password))
             (return-from add-ntlm-user nil))))))
    ;; no free entries remap 
    (close-ntlm-database)
    (open-ntlm-database (* count 2))
    (pounds:with-locked-mapping (*ntlm-stream*)
      (file-position *ntlm-stream* (* +ntlm-block-size+ count))
      (write-ntlm-entry *ntlm-stream*
                        (make-ntlm-entry :active t 
                                         :user username
                                         :password password)))
    nil))
    
(defun find-ntlm-user (username)
  "Lookup the named user's password."
  (open-ntlm-database)
  (let (count)
    (pounds:with-locked-mapping (*ntlm-stream*)
      (setf count (database-count))
      (do ((i 1 (1+ i)))
          ((= i count))
        (let ((entry (read-ntlm-entry *ntlm-stream*)))
          (when (and (ntlm-entry-active entry)
                     (string= (ntlm-entry-user entry) username))
            (return-from find-ntlm-user (ntlm-entry-password entry)))))))
  nil)

(defun list-ntlm-users ()
  "List all entries in the user database."
  (open-ntlm-database)
  (let (count users)
    (pounds:with-locked-mapping (*ntlm-stream*)
      (setf count (database-count))
      (do ((i 1 (1+ i)))
          ((= i count))
        (let ((entry (read-ntlm-entry *ntlm-stream*)))
          (when (ntlm-entry-active entry)
            (push (list :name (ntlm-entry-user entry)
                        :password (ntlm-entry-password entry))
                  users)))))
    users))
  

(defun remove-ntlm-user (username)
  "Delete the named user from the local database."
  (open-ntlm-database)
  (let (count)
    (pounds:with-locked-mapping (*ntlm-stream*)
      (setf count (database-count))
      (do ((i 1 (1+ i)))
          ((= i count))
        (let ((offset (file-position *ntlm-stream*))
              (entry (read-ntlm-entry *ntlm-stream*)))
          (when (and (ntlm-entry-active entry)
                     (string= (ntlm-entry-user entry) username))
            (file-position *ntlm-stream* offset)
            (nibbles:write-ub32/be 0 *ntlm-stream*)
            (return-from remove-ntlm-user nil))))))
  nil)


(defun logon-user (username password &optional domain)
  "Logon the current user using the USERNAME and PASSWORD." 
  (declare (type string username password)
           (type (or string null) domain))
  (open-ntlm-database)
  (setf *default-ntlm-values*
        (make-ntlm :user username
                   :password (password-md4 password)
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
		nil)
	(error 'glass:gss-error :major :defective-credential))))

(defmethod glass:context-principal-name ((context ntlm-context) &key)
  (format nil "~A@~A" (ntlm-context-user context) (ntlm-context-domain context)))


