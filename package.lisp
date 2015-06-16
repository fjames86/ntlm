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
  (:export #:logon-user
           #:find-ntlm-user
           #:remove-ntlm-user
           #:add-ntlm-user
           #:list-ntlm-users
           #:open-ntlm-database
           #:close-ntlm-database
           #:*ntlm-database-path*))

