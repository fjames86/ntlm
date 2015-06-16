;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(asdf:defsystem :ntlm
  :name "NTLM"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "Provides NTLM authentication system to the glass API."
  :license "MIT"
  :version "1.0.1"
  :serial t
  :components
  ((:file "package")
   (:file "messages")
   (:file "security")
   (:file "database")
   (:file "gss"))
  :depends-on (:packet :ironclad :cl-base64 :pounds :glass))

