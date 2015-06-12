;;;; Copyright (c) Frank James 2015 <frank.a.james@gmail.com>
;;;; This code is licensed under the MIT license.

(asdf:defsystem :ntlm
  :name "NTLM"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "Provides NTLM authentication system to the glass API."
  :license "MIT"
  :version "1.0.0"
  :components
  ((:file "package")
   (:file "messages" :depends-on ("package"))
   (:file "security" :depends-on ("messages"))
   (:file "gss" :depends-on ("security")))
  :depends-on (:packet :ironclad :cl-base64 :pounds :glass))



