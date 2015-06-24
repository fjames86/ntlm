;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

;;; This file defines a simple database to store user credentials for locally authenticated users.
;;; Obviously the file is storing plaintext passwords, so look after it!  

(in-package #:ntlm)

;; ------------------------
;; password database

(defvar *ntlm-password-path* (merge-pathnames "ntlm.dat" (user-homedir-pathname)))
(defvar *db* nil)
(defconstant +ntlm-block-size+ 128)

;; layout of each block:
;; <username 32 bytes> <password 32 bytes> <spare>
(defstruct ntlm-entry 
  user password)

(defun read-ntlm-entry (stream)
  (let ((entry (make-ntlm-entry)))
    (let* ((count (nibbles:read-ub32/be stream))
           (buff (nibbles:make-octet-vector count)))
      (read-sequence buff stream)
      (setf (ntlm-entry-user entry) (babel:octets-to-string buff)))
    (let* ((count (nibbles:read-ub32/be stream))
           (buff (nibbles:make-octet-vector count)))
      (read-sequence buff stream)
      (setf (ntlm-entry-password entry) (babel:octets-to-string buff)))
    entry))

(defun write-ntlm-entry (stream entry)
  (declare (type ntlm-entry entry))
  (let ((octets (babel:string-to-octets (ntlm-entry-user entry))))
    (nibbles:write-ub32/be (length octets) stream)
    (write-sequence octets stream))
  (let ((octets (babel:string-to-octets (ntlm-entry-password entry))))
    (nibbles:write-ub32/be (length octets) stream)
    (write-sequence octets stream)))

(defun close-ntlm-database ()
  (when *db*
    (pounds.db:close-db *db*)
    (setf *db* nil)))

(defun open-ntlm-database (&optional (count 32))
  (setf *db* (pounds.db:open-db *ntlm-password-path*
                                #'read-ntlm-entry
                                #'write-ntlm-entry
                                :block-size +ntlm-block-size+
                                :count count)))


(defun add-ntlm-user (username password)
  "Add a new entry into the local database."
  (open-ntlm-database)
  (setf (pounds.db:find-entry username *db*
                              :test #'string-equal
                              :key #'ntlm-entry-user)
        (make-ntlm-entry :user username :password password)))

(defun find-ntlm-user (username)
  "Lookup the named user's password."
  (open-ntlm-database)
  (pounds.db:find-entry username *db*
                        :test #'string-equal
                        :key #'ntlm-entry-user))

(defun list-ntlm-users ()
  "List all entries in the user database."
  (open-ntlm-database)
  (pounds.db:mapentries #'identity *db*))

(defun remove-ntlm-user (username)
  "Delete the named user from the local database."
  (open-ntlm-database)
  (pounds.db:remove-entry username *db*
			  :test #'string-equal
			  :key #'ntlm-entry-user))


