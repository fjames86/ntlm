;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

;;; This shows how you might write an HTTP client that does NTLM authentication
;;; You need drakma and cl-base64 systems.
;;; Try pointing the client at the HTTP server provided by server.c. 

(defpackage #:ntlm.example
  (:use #:cl))

(in-package #:ntlm.example)

;; before running this you must first set things up by calling
;; (ntlm:logon-user "username" "password" "domain")

(defun send-ntlm-http-request (&optional (url "http://localhost:2001/"))
  (let ((creds (gss:acquire-credentials :ntlm nil)))
    (multiple-value-bind (context buffer) (gss:initialize-security-context creds)
      ;; start by sending a regular request 
      (multiple-value-bind (content status-code headers ruri stream must-close reason)
          (drakma:http-request url
                               :additional-headers 
                               `((:authorization . ,(format nil 
                                                            "NTLM ~A" 
                                                            (cl-base64:usb8-array-to-base64-string buffer))))
                               :keep-alive t 
                               :close nil)
        (declare (ignore ruri must-close))
        (case status-code
          (200 (format t "SUCCESS~%")
               (format t "CONTENT:~%")
               (format t "~S~%" content))
          (401 (format t "INITIAL UNAUTHORIZED ~A~%~%" reason)
               ;; extract the WWW-AUTHENTICATE header
               (let ((www (cdr (assoc :www-authenticate headers))))
                 (unless www (error "No WWW-AUTHENTICATE header"))
                 ;; get the buffer from the base64 encoded string 
                 (let ((matches (nth-value 1 (cl-ppcre:scan-to-strings "NTLM ([\\w=\\+/]+)" www))))
                   (unless matches (error "Not an NTLM authenticate message"))
                   (format t "WWW-AUTHENTICATE: ~A~%~%" (elt matches 0))
                   (multiple-value-bind (context buffer)                        
                       (gss:initialize-security-context context
                                                        :buffer 
                                                        (cl-base64:base64-string-to-usb8-array (elt matches 0)))
                     (declare (ignore context))
                     (format t "AUTHORIZATION: ~A~%~%" (format nil "NTLM ~A"
                                                             (cl-base64:usb8-array-to-base64-string buffer)))
                     (multiple-value-bind (content status-code headers ruri stream must-close reason)
                         (drakma:http-request url
                                              :additional-headers 
                                              `((:authorization . ,(format nil "NTLM ~A"
                                                                           (cl-base64:usb8-array-to-base64-string buffer))))
                                              :stream stream)
                       (declare (ignore must-close ruri stream headers))
                       (case status-code 
                         (200 (format t "SUCCESS~%")
                              (format t "CONTENT: ~%")
                              (format t "~S~%" content))
                         (otherwise (format t "FAILED ~A ~A~%" status-code reason))))))))
          (otherwise (format t "FAILED: ~A~%" reason)))))))
