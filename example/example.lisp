;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.


(defpackage #:ntlm-example
  (:use #:cl))

(in-package #:ntlm-example)

;; add an initial entry into the database
(ntlm:add-ntlm-user "frank" "james")

;; -------------------- this should succeed --------------

(ntlm:logon-user "frank" "james" "DOMAIN")

;; client
(defparameter *creds* (gss:acquire-credentials :ntlm nil))
(multiple-value-bind (context buffer) (gss:initialize-security-context *creds*)
	   (defparameter *client-context* context)
	     (defparameter *buffer* buffer))

;; server
(multiple-value-bind (context buffer) (gss:accept-security-context *creds* *buffer*)
	   (defparameter *server-context* context)
	   (defparameter *buffer* buffer))

;; client
(multiple-value-bind (context buffer) (gss:initialize-security-context *client-context* :buffer *buffer*)
	   (defparameter *client-context* context)
	   (defparameter *buffer* buffer))

;; server
(multiple-value-bind (context buffer) (gss:accept-security-context *server-context* *buffer*)
	   (defparameter *server-context* context)
	   (defparameter *buffer* buffer))


;; ------------------- this should fail ------------------------

(ntlm:logon-user "frank" "jamesxxxx" "DOMAIN")

(defparameter *creds* (gss:acquire-credentials :ntlm nil))

(multiple-value-bind (context buffer) (gss:initialize-security-context *creds*)
	   (defparameter *client-context* context)
	     (defparameter *buffer* buffer))

(multiple-value-bind (context buffer) (gss:accept-security-context *creds* *buffer*)
	   (defparameter *server-context* context)
	   (defparameter *buffer* buffer))

(multiple-value-bind (context buffer) (gss:initialize-security-context *client-context* :buffer *buffer*)
	   (defparameter *client-context* context)
	   (defparameter *buffer* buffer))

(multiple-value-bind (context buffer) (gss:accept-security-context *server-context* *buffer*)
	   (defparameter *server-context* context)
	   (defparameter *buffer* buffer))

